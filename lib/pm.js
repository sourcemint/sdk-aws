
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const Q = require("sourcemint-util-js/lib/q");
const TERM = require("sourcemint-util-js/lib/term");
const UTIL = require("sourcemint-util-js/lib/util");
const AWS = require("aws-lib");
const SSH_PM = require("sourcemint-pm-ssh/lib/pm");
const GITHUB = require("sourcemint-sdk-github/lib/github");
const PM = require("sourcemint-pm-sm/lib/pm");
const SM = require("sourcemint-pm-sm/lib/sm");
const CREDENTIALS_SSH = require("sourcemint-credentials-js/lib/ssh");
const MAPPINGS = require("mappings");
const REQUEST = require("request");


// TODO: Relocate much of this to `sourcemint-deloyer` with specific task implementations here.

exports.deploy = function(pm, options) {

    if (!process.env.HOME) {
        TERM.stdout.writenl("\0red(" + "ERROR: " + "`HOME` environment variable not set." + "\0)");
		var deferred = Q.defer();
        deferred.reject(true);
        return deferred.promise;
    }

	var ec2;

	var githubUserInfo = null;
	function credentialsFetcher(namespace, name, options) {
		return Q.call(function() {
			if (!githubUserInfo) {
				return GITHUB.getUserInfo(pm.context.credentials).then(function(info) {
					githubUserInfo = info;
				});
			}
		}).then(function() {

			if (!githubUserInfo) {
				TERM.stdout.writenl("\0red([sm] ERROR: Fetching user info from github! Make sure your `github.com/sourcemint/sdk-github/0` credentials are correct in: " + pm.context.credentials.getPath() + "\0)");
				throw true;
			}

			if (namespace === "github.com/sourcemint/sdk-github/0" && name === "username") {
				return githubUserInfo.login;
			} else
			if (namespace === "github.com/sourcemint/pm-git/0" && name === "user.email") {
				return githubUserInfo.email;
			} else
			if (namespace === "github.com/sourcemint/pm-git/0" && name === "user.name") {
				return githubUserInfo.name;
			}

			return null;
		});
	}

	function deploy(hostname) {

		TERM.stdout.writenl("Deploying to hostname: " + hostname);

		var opts = UTIL.deepCopy(options);

		opts.hostname = hostname;

		var deferred = Q.defer();

        if (!pm.context.platformUri) {
            deferred.reject(new Error("'pm.context.platformUri' not set via `config[\"github.com/sourcemint/deployer/0\"].platform` in '" + pm.context.program.descriptor.path + "'!"));
            return deferred.promise;
        }

		SM.for(pm.context.program.package.path).require({
			location: pm.context.platformUri,
			// TODO: Determine `pm` based on `package.json` of package being located.
			pm: "npm"
		}, function(err) {
			if (err) {
				deferred.reject(err);
				return;
			}

			var packagePath = MAPPINGS.for(pm.context.program.package.path).resolve(pm.context.platformUri.replace(/\//g, "+"));
			var descriptorPath = PATH.join(packagePath, "package.json");
			var descriptor = JSON.parse(FS.readFileSync(descriptorPath));

			ASSERT(typeof descriptor.config === "object", "Did not find `config` in descriptor '" + descriptorPath + "'!");
			ASSERT(typeof descriptor.config["github.com/sourcemint/sdk-aws/0"] === "object", "Did not find `config[\"github.com/sourcemint/sdk-aws/0\"]` in descriptor '" + descriptorPath + "'!");

			var config = descriptor.config["github.com/sourcemint/sdk-aws/0"];

			ASSERT(typeof config.username !== "undefined", "`config.username` is required!");

			opts.username = config.username;
			opts.scriptVars = config.scriptVars;
			if (typeof opts.scriptVars.USERNAME === "undefined") {
				opts.scriptVars.USERNAME = config.username;
			}
			opts.binName = "bash";
			opts.scriptPath = PATH.join(packagePath, "bootstrap.sh");

			pm.context.credentials.requestFor("github.com/sourcemint/pm-git/0", "user.name", {
				fetcher: credentialsFetcher				
			}).then(function(GitUserName) {
				return pm.context.credentials.requestFor("github.com/sourcemint/pm-git/0", "user.email", {
					fetcher: credentialsFetcher				
				}).then(function(GitUserEmail) {
					return pm.context.credentials.requestFor("github.com/sourcemint/sdk-github/0", "username", {
						fetcher: credentialsFetcher				
					}).then(function(GithubUsername) {

						opts.scriptVars.GIT_USER_NAME = GitUserName;
						opts.scriptVars.GIT_USER_EMAIL = GitUserEmail;

						return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "KeyName"])).then(function(KeyName) {

							return Q.when(pm.context.credentials.get("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName), function(keyPath) {

								opts.sshPrivateKeyPath = pm.context.credentials.makeAbsolutePath(keyPath);

								return deployBootstrap(opts).then(function() {
								    return PM.forProgramPath(packagePath, pm).then(function(bootstrapPM) {
								        return PM.forPackagePath(packagePath, bootstrapPM).then(function(bootstrapPM) {

								            return require("sourcemint-pm-rsync/lib/pm").deploy(bootstrapPM, {
								                username: opts.username,
								                hostname: opts.hostname,
								                sshPrivateKeyPath: opts.sshPrivateKeyPath,
								                targetPath: "/pinf/bootstrap"
								            }).then(function() {

												return SSH_PM.deploy(pm, {
									                username: opts.username,
									                hostname: opts.hostname,
									                sshPrivateKeyPath: opts.sshPrivateKeyPath,
													targetPath: "/pinf/bootstrap/provision.config.json",
													data: JSON.stringify({
														"github.com/sourcemint/deployer/0": {
												            "username": opts.username,
												            "hostname": opts.hostname
												        },
												        "c9/0": {
												        	"restrict": [
														        "github/" + GithubUsername
														    ]
												        }
													}, null, 4)
												}).then(function() {

													opts.binName = "bash";
													opts.scriptPath = "/pinf/bootstrap/provision.sh";
									            	return SSH_PM.call(pm, opts);
												});
								            });
								        });
								    });
							    });
						    });
					    });
					});
				});
			}).then(function() {
				opts.config = config;
				return opts;
			}).then(deferred.resolve, deferred.reject);
		});

		return deferred.promise;
	}

	function deployBootstrap(opts) {
		var deferred = Q.defer();

		Q.when(SSH_PM.deploy(pm, opts), deferred.resolve, function(err) {
			if (err.code === "CONNECTION_REFUSED") {

				TERM.stdout.writenl("\0orange(SSH connection refused. Waiting 5 seconds before trying again ...\0)");

				setTimeout(function() {
		  			deployBootstrap(opts).then(deferred.resolve, deferred.reject);
				}, 5 * 1000);
			} else {
				deferred.reject(err);
			}
		});

		return deferred.promise;
	}

	function ensureInstanceTags() {
		var deferred = Q.defer();

		var InstanceId = pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "InstanceId"]);

		ec2.call("DescribeTags", {
			"Filter.1.Name": "resource-id",
			"Filter.1.Value.1": InstanceId
		}, function(err, result) {
			if (err) {
				deferred.reject(err);
				return;
			}

			var existingTags = {};
			if (result.tagSet && result.tagSet.item) {
				if (!UTIL.isArrayLike(result.tagSet.item)) {
					result.tagSet.item = [
						result.tagSet.item
					];
				}
				result.tagSet.item.forEach(function(tag) {
					existingTags[tag.key] = tag.value;
				});
			}

			var tags = {};

			var done = Q.ref();

			if (!existingTags["pinf:email"]) {
				done = Q.when(done, function() {
					return pm.context.credentials.requestFor("github.com/sourcemint/pm-git/0", "user.email", {
						fetcher: credentialsFetcher				
					}).then(function(GitUserEmail) {
						tags["pinf:email"] = GitUserEmail; 
					});
				});
			}

			if (!existingTags["pinf:user"]) {
				done = Q.when(done, function() {
					return pm.context.credentials.requestFor("github.com/sourcemint/sdk-github/0", "username", {
						fetcher: credentialsFetcher				
					}).then(function(Username) {
						tags["pinf:user"] = Username; 
					});
				});
			}

			if (!existingTags["pinf:uid"] && pm.context.program.descriptor.json.uid) {
				tags["pinf:uid"] = pm.context.program.descriptor.json.uid;
			}

			// TODO: Set name based on program descriptor or prompt?
			//tags["pinf:name"] = "Server"; 

			Q.when(done, function() {

				if (UTIL.len(tags) > 0) {

					var args = {
						"ResourceId.1": InstanceId
					};
					var index = 1;
					for (var name in tags) {
						args["Tag." + index + ".Key"] = name;
						args["Tag." + index + ".Value"] = tags[name];
						index += 1;
					}

					TERM.stdout.writenl("Tagging instance.");

					ec2.call("CreateTags", args, function(err, result) {
						if (err) {
							return deferred.reject(err);
						}
					});
				}
			}).when(deferred.resolve, deferred.reject);
		});

		return deferred.promise;
	}

	function findRunningInstance() {

		var InstanceId = pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "InstanceId"]);

		TERM.stdout.writenl("Looking up AWS instance for ID: " + InstanceId);

		var deferred = Q.defer();

		ec2.call("DescribeInstances", {
			"InstanceId": InstanceId
		}, function(err, result) {
			if (err) {
				deferred.reject(err);
				return;
			}

			if (!result.reservationSet.item) {
		        TERM.stdout.writenl("\0red(" + "ERROR: " + "Live instance with ID `" + InstanceId + "` not found! Was it terminated? Check at: https://console.aws.amazon.com/ec2/" + "\0)");
		        deferred.reject(true);
		        return;
			}

			var state = result.reservationSet.item.instancesSet.item.instanceState.name;

			if (state === "pending") {
				TERM.stdout.writenl("\0orange(Instance not running (current state: " + state + "). Waiting 10 seconds before checking again ...\0)");

				setTimeout(function() {
		  			findRunningInstance().then(deferred.resolve, deferred.reject);
				}, 10 * 1000);
			}
			else
			if (state === "running") {
				TERM.stdout.writenl("Found running instance!");

	  			deferred.resolve(result.reservationSet.item.instancesSet.item.dnsName);
	  		} else {
		        TERM.stdout.writenl("\0red(" + "ERROR: " + "Instance not running. Current state: " + state + "\0)");
		        deferred.reject();
		    }
		});

		return deferred.promise;
	}

	function ensureSecurityGroup() {

	    if (!pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]) {
	        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`." + "\0)");
			var deferred = Q.defer();
	        deferred.reject(true);
	        return deferred.promise;
	    }

		var config = UTIL.deepCopy(pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]);

		return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "SecurityGroup"])).then(function(SecurityGroup) {

			return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "modifySecurityGroup"])).then(function(modifySecurityGroup) {

				function verifySecurityGroup(SecurityGroup) {

					TERM.stdout.writenl("Verifying security group '" + SecurityGroup + "'.");

					function provisionGroup() {
			    		var deferred = Q.defer();
						ec2.call("DescribeSecurityGroups", {
							"GroupName": SecurityGroup
						}, function(err, result) {
							if (typeof err === "string" && /The security group .*? does not exist/.test(err)) {

					    		if (modifySecurityGroup === false) {
							        TERM.stdout.writenl("\0red(" + "ERROR: " + "Security group '" + SecurityGroup + "' does not exist! Not auto-provisioning it due to `modifySecurityGroup === false`." + "\0)");
							        return deferred.reject(true);
					    		}

								ec2.call("CreateSecurityGroup", {
									"GroupName": SecurityGroup,
									"GroupDescription": SecurityGroup
								}, function(err, result) {
									if (err) {
										deferred.reject(err);
										return;
									}
									deferred.resolve({
										groupId: result.groupId
									});
								});
							} else {
								// Group exists.
								deferred.resolve(result.securityGroupInfo.item);
							}
						});
						return deferred.promise;
					}

					function provisionRecords(info) {

			    		if (modifySecurityGroup === false) {

							TERM.stdout.writenl("Skip verify/provision records for security group '" + SecurityGroup + "' due to `modifySecurityGroup === false`.");

			    			return Q.ref();
			    		}

			    		var deferred = Q.defer();

			    		// Get our public IP address.
			    		// TODO: Use our own service here.
						REQUEST("http://ipecho.net/plain", function(err, response, ip) {
							if (err) {
								return deferred.reject(err);
							}

				    		var existingRecords = {};

				    		if (info.ipPermissions && info.ipPermissions.item) {
			    				if (!UTIL.isArrayLike(info.ipPermissions.item)) {
			    					info.ipPermissions.item = [ info.ipPermissions.item ];
			    				}
				    			info.ipPermissions.item.forEach(function(record) {
				    				if (!UTIL.isArrayLike(record.ipRanges.item)) {
				    					record.ipRanges.item = [ record.ipRanges.item ];
				    				}
				    				record.ipRanges.item.forEach(function(ipRange) {
					    				existingRecords[
					    					record.ipProtocol + ":" + 
					    					record.fromPort + ":" + 
					    					record.toPort + ":" + 
					    					ipRange.cidrIp
				    					] = record;
				    				});
				    			});
				    		}

				    		var provisionRecords = [];

							// TODO: Allow for custom permissions declared in `program.json`.

				    		if (!existingRecords["tcp:0:65535:" + ip + "/32"]) {
				    			provisionRecords.push({
				    				ipProtocol: "tcp",
				    				fromPort: "0",
				    				toPort: "65535",
				    				cidrIp: ip + "/32"
				    			});
				    		}
				    		if (!existingRecords["udp:0:65535:" + ip + "/32"]) {
				    			provisionRecords.push({
				    				ipProtocol: "udp",
				    				fromPort: "0",
				    				toPort: "65535",
				    				cidrIp: ip + "/32"
				    			});
				    		}
				    		if (!existingRecords["icmp:-1:-1:" + ip + "/32"]) {
				    			provisionRecords.push({
				    				ipProtocol: "icmp",
				    				fromPort: "-1",
				    				toPort: "-1",
				    				cidrIp: ip + "/32"
				    			});
				    		}

							if (provisionRecords.length === 0) {

								deferred.resolve();

							} else {

								var opts = {
									"GroupId": info.groupId
								};

								var index = 1;
								provisionRecords.forEach(function(record) {
									opts["IpPermissions." + index + ".IpProtocol"] = record.ipProtocol;
									opts["IpPermissions." + index + ".FromPort"] = record.fromPort;
									opts["IpPermissions." + index + ".ToPort"] = record.toPort;
									opts["IpPermissions." + index + ".IpRanges.1.CidrIp"] = record.cidrIp;
									index += 1;
								});

								TERM.stdout.writenl("Provisioning " + provisionRecords.length + " records for security group '" + SecurityGroup + "'.");

								ec2.call("AuthorizeSecurityGroupIngress", opts, function(err, result) {
									if (err) {
										deferred.reject(err);
										return;
									}
									deferred.resolve();
								});
							}
						});
						return deferred.promise;
					}
					return provisionGroup().then(provisionRecords);
				}

				var done = Q.ref();

				if (modifySecurityGroup === null) {

					done = Q.when(done, function() {

						if (config.modifySecurityGroup === false) {
							modifySecurityGroup = false;
						} else {
							modifySecurityGroup = true;
						}

						return pm.context.deploymentDescriptor.set(["config", "github.com/sourcemint/sdk-aws/0", "modifySecurityGroup"], modifySecurityGroup);
					});
				}

				return Q.when(done, function() {

					if (SecurityGroup === null) {

						SecurityGroup = SecurityGroup || config.SecurityGroup || pm.context.credentials.requestFor("github.com/sourcemint/sdk-github/0", "username", {
							fetcher: credentialsFetcher				
						}).then(function(Username) {
							return "pinf:user:github.com/" + Username;
						});

						return Q.when(SecurityGroup, function(SecurityGroup) {

							return verifySecurityGroup(SecurityGroup).then(function() {

								TERM.stdout.writenl("Writing security group '" + SecurityGroup + "' to program descriptor '" + pm.context.deploymentDescriptor.path + "' at `config[\"github.com/sourcemint/sdk-aws/0\"].SecurityGroup`");

								return pm.context.deploymentDescriptor.set(["config", "github.com/sourcemint/sdk-aws/0", "SecurityGroup"], SecurityGroup);
							});
						});

					} else {
						return verifySecurityGroup(SecurityGroup);
					}
				});
			});
		});
	}

	function ensureSSHKey() {

	    if (!pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]) {
	        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`." + "\0)");
			var deferred = Q.defer();
	        deferred.reject(true);
	        return deferred.promise;
	    }

		var config = UTIL.deepCopy(pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]);

		return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "KeyName"])).then(function(KeyName) {

			var PrivateKeyPath = null;			

			function verifyKey() {

				TERM.stdout.writenl("Verifying AWS key '" + KeyName + "'.");

	    		var deferred = Q.defer();

				ec2.call("DescribeKeyPairs", {
					"KeyName": KeyName
				}, function(err, result) {

					if (result.Errors && result.Errors.Error && result.Errors.Error.Code === "InvalidKeyPair.NotFound") {

						var privateKey = new CREDENTIALS_SSH.PrivateKey(pm.context.credentials, PrivateKeyPath || "aws-" + KeyName.replace(/[\/:]/g, "+") + "-rsa");

						Q.when(privateKey.getPublicKey(), function(publicKey) {
							PrivateKeyPath = privateKey.path;

							TERM.stdout.writenl("Uploading new AWS key '" + KeyName + "' stored at '" + privateKey.path + "'.");

							ec2.call("ImportKeyPair", {
								"KeyName": KeyName,
								"PublicKeyMaterial": new Buffer(publicKey).toString("base64")
							}, function(err, result) {
								if (err) {
									return deferred.reject(err);
								}
								deferred.resolve();
							});
						}).fail(deferred.reject);

					} else if (err) {
						return deferred.reject(err);
					} else {

						// The key was found on AWS. It should be at `PrivateKeyPath`. If it is not we ask
						// user to locate it.

						Q.call(function() {
							if (!PATH.existsSync(PrivateKeyPath)) {
								return pm.context.credentials.remove("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName).then(function() {
									return pm.context.credentials.requestFor("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName).then(function(keyPath) {
										keyPath = pm.context.credentials.makeAbsolutePath(keyPath);
										if (!PATH.existsSync(keyPath)) {
											return pm.context.credentials.remove("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName).then(function() {
												throw new Error("Private key not found at: " + keyPath);
											});
										}
										PrivateKeyPath = keyPath;
									});
								});
							}
						}).then(function() {

							// TODO: Use `privateKey.getFingerprint()` to compare against fingerprint from AWS.

							deferred.resolve();

						}).fail(deferred.reject);
					}
				});

				return deferred.promise;
			}

			function checkKeyName() {
				if (KeyName === null) {
					var name = KeyName || config.KeyName || pm.context.credentials.requestFor("github.com/sourcemint/sdk-github/0", "username", {
						fetcher: credentialsFetcher				
					}).then(function(Username) {
						return "pinf:user:github.com/" + Username;
					});
					return Q.when(name, function(name) {
						KeyName = name;
					});
				}
			}

			function checkPrivateKeyPath() {
				return Q.when(pm.context.credentials.get("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName), function(keyPath) {
					PrivateKeyPath = pm.context.credentials.makeAbsolutePath(keyPath);
				});
			}

			return Q.when(checkKeyName(), function() {
				return Q.when(checkPrivateKeyPath(), verifyKey);
			}).then(function() {
				return Q.when(pm.context.deploymentDescriptor.set(["config", "github.com/sourcemint/sdk-aws/0", "KeyName"], KeyName), function() {
					return Q.when(pm.context.credentials.set("github.com/sourcemint/sdk-aws/-meta/ec2-PrivateKeyPath/0", KeyName, pm.context.credentials.makeRelativePath(PrivateKeyPath)));
				});
			});
		});
	}

	function createInstance() {

		var config = UTIL.deepCopy(pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]);

	    if (!config.ImageId) {
	        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`.ImageId" + "\0)");
	    	var deferred = Q.defer();
	        deferred.reject();
	        return deferred.promise;
	    }

		return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "SecurityGroup"])).then(function(SecurityGroup) {

			return Q.when(pm.context.deploymentDescriptor.get(["config", "github.com/sourcemint/sdk-aws/0", "KeyName"])).then(function(KeyName) {

				TERM.stdout.writenl("Launching AWS instance based on AMI '" + config.ImageId + "' with key '" + KeyName + "' under security group '" + SecurityGroup + "'.");

				var opts = {
					"ImageId": config.ImageId,
					"MinCount": 1,
					"MaxCount": 1,
					"InstanceType": "t1.micro",
					"SecurityGroup": SecurityGroup,
					"KeyName": KeyName
				};
				if (config.InstanceType) opts.InstanceType = config.InstanceType;

				var deferred = Q.defer();

				ec2.call("RunInstances", opts, function(err, result) {
					if (err) {
						deferred.reject(err);
						return;
					}

					var InstanceId = result.instancesSet.item.instanceId;

					TERM.stdout.writenl("Writing instance ID '" + InstanceId + "' to program descriptor '" + pm.context.deploymentDescriptor.path + "' at `config[\"github.com/sourcemint/sdk-aws/0\"].InstanceId`");

					return pm.context.deploymentDescriptor.set(["config", "github.com/sourcemint/sdk-aws/0", "InstanceId"], InstanceId).then(deferred.resolve, deferred.reject);
				});

				return deferred.promise;
			});
		});
	}

	return pm.context.credentials.requestFor("github.com/sourcemint/sdk-aws/0", "AccessKeyId").then(function(AccessKeyId) {
		return pm.context.credentials.requestFor("github.com/sourcemint/sdk-aws/0", "SecretAccessKey", {
// @bug https://github.com/flatiron/prompt/issues/59 			
//			hidden: true
		}).then(function(SecretAccessKey) {

			ec2 = AWS.createEC2Client(AccessKeyId, SecretAccessKey);

			ec2.version = "2012-07-20";

			function prepare() {
				return findRunningInstance().then(function(hostname) {
					return ensureInstanceTags().then(function() {
						return deploy(hostname);
					});
				});
			}

			if (pm.context.deploymentDescriptor.has(["config", "github.com/sourcemint/sdk-aws/0", "InstanceId"])) {
				// TODO: If `options.bore` is set call `ensureSecurityGroup()` to ensure our public IP has access.
				return prepare();
			} else {
				return ensureSSHKey().then(function() {
					return ensureSecurityGroup().then(function() {
						return createInstance().then(prepare);
					});
				});
			}
		});
	}).then(function(sshOptions) {

		return {
			username: sshOptions.username,
			hostname: sshOptions.hostname,
			scriptVars: sshOptions.scriptVars,
			programsPath: "/pinf/programs",
			sshPrivateKeyPath: sshOptions.sshPrivateKeyPath
		};
	});
}

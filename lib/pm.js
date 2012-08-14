
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const Q = require("sourcemint-util-js/lib/q");
const TERM = require("sourcemint-util-js/lib/term");
const UTIL = require("sourcemint-util-js/lib/util");
const AWS = require("aws-lib");
const SSH_PM = require("sourcemint-pm-ssh/lib/pm");
const PM = require("sourcemint-pm-sm/lib/pm");
const SM = require("sourcemint-pm-sm/lib/sm");
const MAPPINGS = require("mappings");


exports.deploy = function(pm, options) {

    if (!pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]) {
        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`." + "\0)");
		var deferred = Q.defer();
        deferred.reject(true);
        return deferred.promise;
    }

    if (!process.env.HOME) {
        TERM.stdout.writenl("\0red(" + "ERROR: " + "`HOME` environment variable not set." + "\0)");
		var deferred = Q.defer();
        deferred.reject(true);
        return deferred.promise;
    }

	var config = UTIL.deepCopy(pm.context.program.descriptor.json.config["github.com/sourcemint/sdk-aws/0"]);
	var ec2;

	function deploy(hostname) {

		TERM.stdout.writenl("Deploying to hostname: " + hostname);

		var opts = UTIL.deepCopy(options);

		opts.hostname = hostname;

		var deferred = Q.defer();

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
			deployBootstrap(opts).then(function() {

			    return PM.forProgramPath(packagePath).then(function(bootstrapPM) {
			        return PM.forPackagePath(packagePath, bootstrapPM).then(function(bootstrapPM) {
			            return require("sourcemint-pm-rsync/lib/pm").deploy(bootstrapPM, {
			                username: opts.username,
			                hostname: opts.hostname,
			                targetPath: "/pinf/bootstrap"
			            }).then(function() {

							opts.binName = "bash";
							opts.scriptPath = "/pinf/bootstrap/provision.sh";
			            	return SSH_PM.call(pm, opts);
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

	function createInstance(KeyName) {

		var deferred = Q.defer();

	    if (!config.ImageId) {
	        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`.ImageId" + "\0)");
	        deferred.reject();
	        return deferred.promise;
	    }
	    if (!config.SecurityGroup) {
	        TERM.stdout.writenl("\0red(" + "ERROR: " + "Program descriptor '" + pm.context.program.descriptor.path + "' does not specify `config[\"github.com/sourcemint/sdk-aws/0\"]`.SecurityGroup" + "\0)");
	        deferred.reject();
	        return deferred.promise;
	    }

		TERM.stdout.writenl("Launching AWS instance based on AMI: " + config.ImageId);

		var opts = {
			"ImageId": config.ImageId,
			"MinCount": 1,
			"MaxCount": 1,
			"InstanceType": "t1.micro",
			"SecurityGroup": config.SecurityGroup,
			"KeyName": KeyName
		};
		if (config.InstanceType) opts.InstanceType = config.InstanceType;

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
	}

	return pm.context.credentials.requestFor("aws.amazon.com", "AccessKeyId").then(function(AccessKeyId) {
	return pm.context.credentials.requestFor("aws.amazon.com", "SecretAccessKey").then(function(SecretAccessKey) {
	return pm.context.credentials.requestFor("aws.amazon.com", "KeyName").then(function(KeyName) {

		ec2 = AWS.createEC2Client(AccessKeyId, SecretAccessKey);

		if (pm.context.deploymentDescriptor.has(["config", "github.com/sourcemint/sdk-aws/0", "InstanceId"])) {
			return findRunningInstance().then(deploy);
		} else {
			return createInstance(KeyName).then(function() {
				return findRunningInstance().then(deploy);
			});
		}
	});
	});
	}).then(function(sshOptions) {

		return {
			username: sshOptions.username,
			hostname: sshOptions.hostname,
			scriptVars: sshOptions.scriptVars,
			programsPath: "/pinf/programs"
		};
	});
}

var utils = require("./utils");
var	url = require("url");
var https = require('https');

var fs = require("fs");
var path = require("path");

// var momenttz = require("moment-timezone");

var rst = fs.readFileSync(path.join(__dirname, "wstrust.template")).toString();

// Current iteration will only support usernameMixed, can look at adding Certificate and other options later
exports.requestSecurityToken = function(options, callback, errorCallback) {
	if (!options.endpoint)
		throw new Error("Expect an Endpoint");
	if (!options.username)
		throw new Error("Expect a username");
	if (!options.password)
		throw new Error("Expect a password");
	if (!options.audience)
		throw new Error("Expect an audience");

	options.keytype = options.keytype || 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
	options.requesttype = options.requesttype || 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue';
	options.tokentype = options.tokentype || 'urn:oasis:names:tc:SAML:2.0:assertion';

	var message = rst;
	try {
		message = message.replace("[To]", options.endpoint);
		message = message.replace("[Username]", options.username);
		message = message.replace("[Password]", options.password);
		message = message.replace("[ApplyTo]", options.scope);
		message = message.replace("[keytype]", options.keytype);
		message = message.replace("[requesttype]", options.requesttype);
		message = message.replace("[tokentype]", options.tokentype);
	} catch(err){
		return utils.reportError(err, callback);
	}

	var uri = url.parse(options.endpoint);

	var post_options = {
		host: uri.host,
		port: '443',
		path: uri.pathname,
		method: 'POST',
		headers: {
			'Content-Type': 'application/soap+xml; charset=utf-8',
			'Content-Length': message.length
		}
	};

	var req = https.request(post_options, function(res) {
		res.setEncoding('utf8');
		res.on('data', function(data) {
			var rstr = {
				token: parseRstr(data),
				response: res
			};
			callback(rstr);
		});
	});

	req.write(message);
	req.end();
	req.on('error', function (e) {
		errorCallback(e);
	});
};

// Parses the RequestSecurityTokenResponse
function parseRstr(rstr){
	var startOfAssertion = rstr.indexOf('<Assertion ');
	var endOfAssertion = rstr.indexOf('</Assertion>') + '</Assertion>'.length;
	var token = rstr.substring(startOfAssertion, endOfAssertion);
	return token;
}

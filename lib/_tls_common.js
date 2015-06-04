// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var net = require('net');
var url = require('url');
var util = require('util');
var constants = require('constants');
var tls = require('tls');

// Lazily loaded
var crypto = null;

var binding = process.binding('crypto');
var NativeSecureContext = binding.SecureContext;

var CONTEXT_DEFAULT_OPTIONS = undefined;

function getSecureOptions(secureProtocol, secureOptions) {
  if (CONTEXT_DEFAULT_OPTIONS === undefined) {
    CONTEXT_DEFAULT_OPTIONS = 0;

    if (!binding.SSL3_ENABLE)
      CONTEXT_DEFAULT_OPTIONS |= constants.SSL_OP_NO_SSLv3;

    if (!binding.SSL2_ENABLE)
      CONTEXT_DEFAULT_OPTIONS |= constants.SSL_OP_NO_SSLv2;
  }

  if (secureOptions === undefined) {
    if (secureProtocol === undefined ||
        secureProtocol === 'SSLv23_method' ||
        secureProtocol === 'SSLv23_server_method' ||
        secureProtocol === 'SSLv23_client_method') {
      secureOptions |= CONTEXT_DEFAULT_OPTIONS;
    }
  }

  return secureOptions;
}
exports._getSecureOptions = getSecureOptions;

function SecureContext(secureProtocol, flags, context) {
  if (!(this instanceof SecureContext)) {
    return new SecureContext(secureProtocol, flags, context);
  }

  if (context) {
    this.context = context;
  } else {
    this.context = new NativeSecureContext();

    if (secureProtocol) {
      this.context.init(secureProtocol);
    } else {
      this.context.init();
    }
  }

  flags = getSecureOptions(secureProtocol, flags);

  this.context.setOptions(flags);
}

exports.SecureContext = SecureContext;


exports.createSecureContext = function createSecureContext(options, context) {
  if (!options) options = {};

  var secureOptions = options.secureOptions;
  if (options.honorCipherOrder)
    secureOptions |= constants.SSL_OP_CIPHER_SERVER_PREFERENCE;

  var c = new SecureContext(options.secureProtocol, secureOptions, context);

  if (context) return c;

  if (options.key) {
    if (Array.isArray(options.key)) {
      for (var i = 0; i < options.key.length; i++) {
        var key = options.key[i];

        if (key.passphrase)
          c.context.setKey(key.pem, key.passphrase);
        else
          c.context.setKey(key);
      }
    } else {
      if (options.passphrase) {
        c.context.setKey(options.key, options.passphrase);
      } else {
        c.context.setKey(options.key);
      }
    }
  }

  // NOTE: It's important to add CA before the cert to be able to load
  // cert's issuer in C++ code.
  if (options.ca) {
    if (util.isArray(options.ca)) {
      for (var i = 0, len = options.ca.length; i < len; i++) {
        c.context.addCACert(options.ca[i]);
      }
    } else {
      c.context.addCACert(options.ca);
    }
  } else {
    c.context.addRootCerts();
  }

  if (options.cert) {
    if (Array.isArray(options.cert)) {
      for (var i = 0; i < options.cert.length; i++)
        c.context.setCert(options.cert[i]);
    } else {
      c.context.setCert(options.cert);
    }
  }

  if (options.ciphers)
    c.context.setCiphers(options.ciphers);
  else
    c.context.setCiphers(tls.DEFAULT_CIPHERS);

  if (util.isUndefined(options.ecdhCurve))
    c.context.setECDHCurve(tls.DEFAULT_ECDH_CURVE);
  else if (options.ecdhCurve)
    c.context.setECDHCurve(options.ecdhCurve);

  if (options.dhparam) c.context.setDHParam(options.dhparam);

  if (options.crl) {
    if (util.isArray(options.crl)) {
      for (var i = 0, len = options.crl.length; i < len; i++) {
        c.context.addCRL(options.crl[i]);
      }
    } else {
      c.context.addCRL(options.crl);
    }
  }

  if (options.sessionIdContext) {
    c.context.setSessionIdContext(options.sessionIdContext);
  }

  if (options.pfx) {
    var pfx = options.pfx;
    var passphrase = options.passphrase;

    if (!crypto)
      crypto = require('crypto');

    pfx = crypto._toBuf(pfx);
    if (passphrase)
      passphrase = crypto._toBuf(passphrase);

    if (passphrase) {
      c.context.loadPKCS12(pfx, passphrase);
    } else {
      c.context.loadPKCS12(pfx);
    }
  }

  return c;
};

exports.translatePeerCertificate = function translatePeerCertificate(c) {
  if (!c)
    return null;

  if (c.issuer) c.issuer = tls.parseCertString(c.issuer);
  if (c.issuerCertificate && c.issuerCertificate !== c) {
    c.issuerCertificate = translatePeerCertificate(c.issuerCertificate);
  }
  if (c.subject) c.subject = tls.parseCertString(c.subject);
  if (c.infoAccess) {
    var info = c.infoAccess;
    c.infoAccess = {};

    // XXX: More key validation?
    info.replace(/([^\n:]*):([^\n]*)(?:\n|$)/g, function(all, key, val) {
      if (key === '__proto__')
        return;

      if (c.infoAccess.hasOwnProperty(key))
        c.infoAccess[key].push(val);
      else
        c.infoAccess[key] = [val];
    });
  }
  return c;
}

exports.DEFAULT_ECDH_CURVE = 'prime256v1';

// Allow {CLIENT_RENEG_LIMIT} client-initiated session renegotiations
// every {CLIENT_RENEG_WINDOW} seconds. An error event is emitted if more
// renegotations are seen. The settings are applied to all remote client
// connections.
exports.CLIENT_RENEG_LIMIT = 3;
exports.CLIENT_RENEG_WINDOW = 600;

exports.SLAB_BUFFER_SIZE = 10 * 1024 * 1024;

exports.getCiphers = function() {
  var names = process.binding('crypto').getSSLCiphers();
  // Drop all-caps names in favor of their lowercase aliases,
  var ctx = {};
  names.forEach(function(name) {
    if (/^[0-9A-Z\-]+$/.test(name)) name = name.toLowerCase();
    ctx[name] = true;
  });
  return Object.getOwnPropertyNames(ctx).sort();
};

// Convert protocols array into valid OpenSSL protocols list
// ("\x06spdy/2\x08http/1.1\x08http/1.0")
exports.convertNPNProtocols = function convertNPNProtocols(NPNProtocols, out) {
  // If NPNProtocols is Array - translate it into buffer
  if (util.isArray(NPNProtocols)) {
    var buff = new Buffer(NPNProtocols.reduce(function(p, c) {
      return p + 1 + Buffer.byteLength(c);
    }, 0));

    NPNProtocols.reduce(function(offset, c) {
      var clen = Buffer.byteLength(c);
      buff[offset] = clen;
      buff.write(c, offset + 1);

      return offset + 1 + clen;
    }, 0);

    NPNProtocols = buff;
  }

  // If it's already a Buffer - store it
  if (util.isBuffer(NPNProtocols)) {
    out.NPNProtocols = NPNProtocols;
  }
};

exports.checkServerIdentity = function checkServerIdentity(host, cert) {
  // Create regexp to much hostnames
  function regexpify(host, wildcards) {
    // Add trailing dot (make hostnames uniform)
    if (!/\.$/.test(host)) host += '.';

    // The same applies to hostname with more than one wildcard,
    // if hostname has wildcard when wildcards are not allowed,
    // or if there are less than two dots after wildcard (i.e. *.com or *d.com)
    //
    // also
    //
    // "The client SHOULD NOT attempt to match a presented identifier in
    // which the wildcard character comprises a label other than the
    // left-most label (e.g., do not match bar.*.example.net)."
    // RFC6125
    if (!wildcards && /\*/.test(host) || /[\.\*].*\*/.test(host) ||
        /\*/.test(host) && !/\*.*\..+\..+/.test(host)) {
      return /$./;
    }

    // Replace wildcard chars with regexp's wildcard and
    // escape all characters that have special meaning in regexps
    // (i.e. '.', '[', '{', '*', and others)
    var re = host.replace(
        /\*([a-z0-9\\-_\.])|[\.,\-\\\^\$+?*\[\]\(\):!\|{}]/g,
        function(all, sub) {
          if (sub) return '[a-z0-9\\-_]*' + (sub === '-' ? '\\-' : sub);
          return '\\' + all;
        });

    return new RegExp('^' + re + '$', 'i');
  }

  var dnsNames = [],
      uriNames = [],
      ips = [],
      matchCN = true,
      valid = false;

  // There're several names to perform check against:
  // CN and altnames in certificate extension
  // (DNS names, IP addresses, and URIs)
  //
  // Walk through altnames and generate lists of those names
  if (cert.subjectaltname) {
    cert.subjectaltname.split(/, /g).forEach(function(altname) {
      if (/^DNS:/.test(altname)) {
        dnsNames.push(altname.slice(4));
      } else if (/^IP Address:/.test(altname)) {
        ips.push(altname.slice(11));
      } else if (/^URI:/.test(altname)) {
        var uri = url.parse(altname.slice(4));
        if (uri) uriNames.push(uri.hostname);
      }
    });
  }

  // If hostname is an IP address, it should be present in the list of IP
  // addresses.
  if (net.isIP(host)) {
    valid = ips.some(function(ip) {
      return ip === host;
    });
  } else {
    // Transform hostname to canonical form
    if (!/\.$/.test(host)) host += '.';

    // Otherwise check all DNS/URI records from certificate
    // (with allowed wildcards)
    dnsNames = dnsNames.map(function(name) {
      return regexpify(name, true);
    });

    // Wildcards ain't allowed in URI names
    uriNames = uriNames.map(function(name) {
      return regexpify(name, false);
    });

    dnsNames = dnsNames.concat(uriNames);

    if (dnsNames.length > 0) matchCN = false;

    // Match against Common Name (CN) only if no supported identifiers are
    // present.
    //
    // "As noted, a client MUST NOT seek a match for a reference identifier
    //  of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
    //  URI-ID, or any application-specific identifier types supported by the
    //  client."
    // RFC6125
    if (matchCN) {
      var commonNames = cert.subject.CN;
      if (util.isArray(commonNames)) {
        for (var i = 0, k = commonNames.length; i < k; ++i) {
          dnsNames.push(regexpify(commonNames[i], true));
        }
      } else {
        dnsNames.push(regexpify(commonNames, true));
      }
    }

    valid = dnsNames.some(function(re) {
      return re.test(host);
    });
  }

  return valid;
};

// Example:
// C=US\nST=CA\nL=SF\nO=Joyent\nOU=Node.js\nCN=ca1\nemailAddress=ry@clouds.org
exports.parseCertString = function parseCertString(s) {
  var out = {};
  var parts = s.split('\n');
  for (var i = 0, len = parts.length; i < len; i++) {
    var sepIndex = parts[i].indexOf('=');
    if (sepIndex > 0) {
      var key = parts[i].slice(0, sepIndex);
      var value = parts[i].slice(sepIndex + 1);
      if (key in out) {
        if (!util.isArray(out[key])) {
          out[key] = [out[key]];
        }
        out[key].push(value);
      } else {
        out[key] = value;
      }
    }
  }
  return out;
};

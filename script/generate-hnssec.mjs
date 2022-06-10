


///  N A T I V E

import { createRequire } from "module";
import { createWriteStream, existsSync, mkdirSync, readFile, readFileSync, writeFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const __get = createRequire(import.meta.url);

///  M O D U L E

const { AuthServer, dnssec, constants, tlsa } = __get("bns");
const { default: chronver } = __get("chronver");
const { encoding, rsa, SHA256 } = __get("bcrypto");
const { zip } = __get("zip-a-folder");
const archiver = __get("archiver");
const arg = __get("arg");
const Config = __get("bcfg");
const dedent = __get("dedent");
const handlebars = __get("handlebars");

///  U T I L

const { KSK, ZONE } = dnssec.keyFlags;
const { pem, x509 } = encoding;
const { RSASHA256 } = dnssec.algs;
const { types } = constants;
const __dirname = dirname(fileURLToPath(import.meta.url));
const backupFolder = join(__dirname, "..", "backup");
const configFolder = join(__dirname, "..", "output");

export const args = arg({
  // Types
  "--host": String,
  "--many": Boolean,
  "--name": String,
  "--verbose": Boolean,
  // Aliases
  "-h": "--host",
  "-m": "--many",
  "-n": "--name",
  "-v": "--verbose"
});



///  P R O G R A M

!args["--many"] ?
  run(args) :
  null;

export function run(suppliedArgs) {
  if (suppliedArgs) {
    switch(true) {
      case !suppliedArgs["--host"]:
        console.error("[dolo] Must provide host");

      case !suppliedArgs["--name"]:
        console.error("[dolo] Must provide name");

      case !suppliedArgs["--host"]:
      case !suppliedArgs["--name"]:
        return;

      default:
        break;
    }
  } else {
    switch(true) {
      case !args["--host"]:
        console.error("[dolo] Must provide host");

      case !args["--name"]:
        console.error("[dolo] Must provide name");

      case !args["--host"]:
      case !args["--name"]:
        return;

      default:
        break;
    }
  }

  const options = {
    host: args["--host"] || suppliedArgs && suppliedArgs["--host"],
    name: args["--name"] || suppliedArgs && suppliedArgs["--name"],
    verbose: (args["--verbose"] || suppliedArgs && suppliedArgs["--verbose"]) || false
  };

  try {
    generateCerts(options);
    generateKeys(options);
    generateZoneFile(options);
    generateReadme(options);
  } catch(_) {
    console.group("[error]");
    console.error(_);
    console.groupEnd();
  } finally {
    generateBackup(options);
  }
}

function generateBackup(options) {
  makeDirectorySyncRecursive(backupFolder);
  const { name, verbose } = options;
  const archive = archiver("zip", { zlib: { level: 9 }});
  const output = createWriteStream(join(backupFolder, `${generateBackupFilename(name)}.zip`));
  const sourceFolder = join(configFolder, name);

  if (!existsSync(sourceFolder)) {
    console.error(`\n[dolo] folder does not exist:\n${indent(sourceFolder, 7)}`);
    return false;
  }

  archive.on("error", err => { throw err; });
  archive.on("warning", err => {
    if (err.code === "ENOENT")
      console.log(err.toString());
    else
      throw err;
  });

  archive.directory(sourceFolder, false);
  archive.pipe(output);
  archive.finalize();

  output.on("close", () => {
    console.log("\n[dolo] Export finished:");
    console.log(indent(`${name}/`, 7));
  });
}

function generateCerts(options) {
  const { host, name, verbose } = options;
  let ipaddr = "";

  verbose && console.log("\n[dolo] Generating TLS key and self-signed certificate…");

  // Create key pair and get JSON for pubkey
  const priv = rsa.privateKeyGenerate(2048);
  const pub = rsa.publicKeyCreate(priv);
  const pubJSON = rsa.publicKeyExport(pub);

  // Timestamps and serial number
  // Use *yesterday* for start time to avoid UTC/timezone conflict
  const date = new Date();
  const month = date.getMonth() + 1;
  const day = date.getDate();

  if (day > 1) {
    date.setDate(day - 1);
  } else {
    date.setMonth((month + 11) % 12);
    date.setDate(30);
  }

  const serial =
    String(date.getFullYear()) +
    ("0" + String(month)).slice(-2) +
    ("0" + String(day)).slice(-2) +
    "00";

  const notBefore = date.toISOString().split(".")[0] + "Z";
  const notAfter = date.toISOString().split(".")[0] + "Z";

  date.setMonth(date.getMonth() + 3);

  // hex-encode IP address
  const bytes = host.split(".");

  for (const byte of bytes)
    ipaddr += Buffer.from([parseInt(byte)]).toString("hex");

  // Basic details, leave out optional and more complex stuff
  const tbsJSON = {
    extensions: [
      {
        critical: false,
        extnID: "SubjectAltName",
        extnValue: [
          {
            node: name,
            type: "DNSName"
          },
          {
            node: `*.${name}`,
            type: "DNSName"
          },
          {
            node: ipaddr,
            type: "IPAddress"
          }
        ]
      },
      {
        critical: false,
        extnID: "BasicConstraints",
        extnValue: {
          cA: false,
          pathLenConstraint: 0
        }
      },
      {
        critical: false,
        extnID: "KeyUsage",
        extnValue: [
          "digitalSignature",
          "nonRepudiation",
          "keyEncipherment",
          "dataEncipherment"
        ]
      }
    ],
    issuer: [],
    serialNumber: serial,
    signature: {
      algorithm: "RSASHA256",
      parameters: {
        node: null,
        type: "NULL"
      }
    },
    subject: [],
    subjectPublicKeyInfo: {
      algorithm: {
        algorithm: "RSAPublicKey",
        parameters: {
          node: null,
          type: "NULL"
        }
      },
      publicKey: {
        modulus: pubJSON.n,
        publicExponent: pubJSON.e
      }
    },
    validity: {
      notBefore: {
        node: notBefore,
        type: "UTCTime"
      },
      notAfter: {
        node: notAfter,
        type: "UTCTime"
      }
    },
    version: 2
  };

  // Create to-be-signed certificate object
  const tbs = x509.TBSCertificate.fromJSON(tbsJSON);

  // Use helper functions for the complicated details
  tbs.issuer = x509.Entity.fromJSON({ COMMONNAME: name });
  tbs.subject = x509.Entity.fromJSON({ COMMONNAME: name });

  // Serialize
  const msg = SHA256.digest(tbs.encode());

  // Sign
  const sig = rsa.sign("SHA256", msg, priv);

  // Complete
  const cert = new x509.Certificate();
  cert.tbsCertificate = tbs;

  cert.signatureAlgorithm.fromJSON({
    algorithm: "RSASHA256",
    parameters: {
      node: null,
      type: "NULL"
    }
  });

  cert.signature.fromJSON({
    bits: sig.length * 8,
    value: sig.toString("hex")
  });

  // Output TLS
  writeFileSyncRecursive(
    join(configFolder, name, "tls", `${name}.crt`),
    cert.toPEM()
  );

  writeFileSyncRecursive(
    join(configFolder, name, "tls", `${name}.key`),
    pem.toPEM(priv, "RSA PRIVATE KEY")
  );

  verbose && console.log(indent("Key and certificate saved\n", 7));
}

function generateKeys(options) {
  const { host, name, verbose } = options;
  const namePlusDot = `${name}.`;

  verbose && console.log("[dolo] Generating DNSSEC keys…");

  const kpriv = dnssec.createPrivate(RSASHA256, 2048);
  const kkey = dnssec.makeKey(namePlusDot, RSASHA256, kpriv, ZONE | KSK);
  const kFilePath = join(configFolder, name, "ksk");
  makeDirectorySyncRecursive(kFilePath);
  dnssec.writeKeys(kFilePath, kkey, kpriv);

  const zpriv = dnssec.createPrivate(RSASHA256, 2048);
  const zkey = dnssec.makeKey(namePlusDot, RSASHA256, zpriv, ZONE);
  const zFilePath = join(configFolder, name, "zsk");
  makeDirectorySyncRecursive(zFilePath);
  dnssec.writeKeys(zFilePath, zkey, zpriv);

  verbose && console.log(indent("Writing new output.conf file…", 7));

  const outputFile = dedent`
    domain: ${namePlusDot}
    host: ${host}
    kskkey: ${dnssec.filename(namePlusDot, kkey.data.algorithm, kkey.data.keyTag())}.key
    kskpriv: ${dnssec.filename(namePlusDot, kkey.data.algorithm, kkey.data.keyTag())}.private
    zskkey: ${dnssec.filename(namePlusDot, zkey.data.algorithm, zkey.data.keyTag())}.key
    zskpriv: ${dnssec.filename(namePlusDot, zkey.data.algorithm, zkey.data.keyTag())}.private
  `;

  writeFileSyncRecursive(join(configFolder, name, "output.conf"), outputFile);
  const ds = dnssec.createDS(kkey);

  const recordRoot = ds.toString().replace("  ", " "); // get rid of double spaces
  const recordRootDescription = "DS record for root zone:";
  const recordDS = `${ds.data.keyTag} ${ds.data.algorithm} ${ds.data.digestType} ${ds.data.digest.toString("hex")}`;
  const recordGlue = `ns.${namePlusDot} ${host}`;
  const recordNS = `ns.${namePlusDot}`;

  verbose && console.log(indent(`\n${recordRootDescription}`, 7));
  verbose && console.log(indent(recordRoot, 7));

  verbose && console.log(indent("\nBob Wallet records:", 7));
  verbose && console.log(indent(`DS:    ${recordDS}`, 7));
  verbose && console.log(indent(`GLUE4: ${recordGlue}`, 7));
  verbose && console.log(indent(`NS:    ${recordNS}`, 7));

  verbose && console.log(indent("\nWriting new records.conf file…", 7));

  const recordsFile = dedent`
    ${recordRootDescription}
    ${recordRoot}

    Bob Wallet records:
    DS:    ${recordDS}
    GLUE4: ${recordGlue}
    NS:    ${recordNS}
  `;

  writeFileSyncRecursive(join(configFolder, name, "records.conf"), recordsFile);

  // const json = {
  //   records: [
  //     {
  //       address: `${host}`,
  //       ns: `ns.${namePlusDot}`,
  //       type: "GLUE4"
  //     },
  //     {
  //       algorithm: ds.data.algorithm,
  //       digest: ds.data.digest.toString("hex"),
  //       digestType: ds.data.digestType,
  //       keyTag: ds.data.keyTag,
  //       type: "DS"
  //     }
  //   ]
  // };

  // writeFileSyncRecursive(join(configFolder, name, "hsw-rpc_sendupdate.txt"), JSON.stringify(json));

  // verbose && console.log(indent("\nAll records, hsw-rpc sendupdate format:\n", 7));
  // verbose && console.log(indent(JSON.stringify(json, null, 2), 7));

  verbose && console.log(indent("\nKeys and config saved", 7));
}

function generateReadme(options) {
  const { name } = options;
  const config = new Config("output");

  config.prefix = "";
  config.parseArg();
  config.open(join(configFolder, name, "output.conf"));

  const { kskkey, zskkey } = config.data;

  const json = {
    domain: name,
    ksk_filename: kskkey.split(".key")[0],
    zsk_filename: zskkey.split(".key")[0]
  };

  readFile(resolve("template.md"), async(err, data) => {
    if (err) {
      console.group("[error]");
      console.error(err);
      console.groupEnd();
      return false;
    }

    const source = data.toString();
    writeFileSyncRecursive(join(configFolder, name, "README.md"), renderToString(source, json));
  });
}

function generateZoneFile(options) {
  const { name, verbose } = options;
  const config = new Config("output");
  let records = [];

  config.prefix = "";
  config.parseArg();
  config.open(join(configFolder, name, "output.conf"));

  const authns = new AuthNS({
    domain: config.str("domain"),
    host: config.str("host"),
    kskkey: config.str("kskkey"),
    kskpriv: config.str("kskpriv"),
    test: config.bool("test", false),
    zskkey: config.str("zskkey"),
    zskpriv: config.str("zskpriv")
  });

  // $TTL 604800

  const intro = dedent`
    ;
    ; ZONE data file for ${authns.domain.slice(0, -1).toUpperCase()}
    ;

    $ORIGIN ${authns.domain}

    @ IN SOA ns.${authns.domain} admin.nic.${authns.domain} (
            202204061   ; SERIAL ; current date (ChronVer) + increment
               604800   ; REFRESH
                86400   ; RETRY
              2419200   ; EXPIRE
               604800 ) ; MINIMUM

    ;
    ; Nameserver Info
    ;

    @ IN NS ns.${authns.domain}
    @ IN A ${authns.host}
    ; @ IN AAAA <your nameserver IPV6 address>
    ns.${authns.domain} IN ${authns.host}

    ;
    ; Domain/Website Info
    ;

    ${authns.domain} IN NS ns.${authns.domain}
    ; ${authns.domain} IN A <your webserver IPV4 address>
    ; ${authns.domain} IN AAAA <your webserver IPV6 address>

    ;
    ; DANE/DNSSEC
    ;
  `;

  // records.push(dedent`
  //   ; Signing Keys
  //   $INCLUDE "/etc/bind/keys/${config.data.domain.slice(0, -1)}/${config.data.zskkey}" #myzsk
  //   $INCLUDE "/etc/bind/keys/${config.data.domain.slice(0, -1)}/${config.data.kskkey}" #myksk

  //   ; Zone Info
  // `);

  verbose && console.log(`\n[dolo] Writing new ${authns.domain}zone file…`);
  authns.init();

  authns.server.zone.names.forEach(recordMap => {
    recordMap.rrs.forEach(rr => records = records.concat(rr));
    recordMap.sigs.forEach(rr => records = records.concat(rr));
  });

  const path = join(configFolder, name, `db.${authns.domain.slice(0, -1)}`);
  const zone = toZone(records)
    // unnecessary entry, we already placed it in the intro
    .replace(`${authns.domain} 21600 IN A ${authns.host}`, "")
    // removes multiple blank lines
    .replace(/(?:)\n{3,}/g, "\n\n")
    // removes multiple spaces within records
    .replace(/  +/g, " ")
    // adds a single blank line at the end of file
    .trimRight() + "\n";

  writeFileSyncRecursive(path, intro.concat("", zone));
  verbose && console.log(indent("Zone file saved", 7));
}



///  H E L P E R

function AuthNS(options) {
  this.domain = options.domain;
  this.host = options.host;
  this.kskkey = options.kskkey;
  this.kskpriv = options.kskpriv;
  this.name = options.domain.slice(0, -1);
  this.port = options.test ?
    53530 :
    53;
  this.server = new AuthServer({
    dnssec: true,
    edns: true,
    tcp: true
  });
  this.zskkey = options.zskkey;
  this.zskpriv = options.zskpriv;

  this.init = function() {
    this.server.setOrigin(this.domain);
    const zone = this.server.zone;

    // Create SOA
    // zone.fromString(
    //   `${this.domain} 21600 IN SOA ns.${this.domain} email.${this.domain} ` +
    //   parseInt(Date.now() / 1000) + " 86400 7200 604800 300"
    // );

    // Create self-referencing NS and glue
    // zone.fromString(`${this.domain} 21600 IN NS ns.${this.domain}`);
    // zone.fromString(`ns.${this.domain} 21600 IN A ${this.host}`);

    // Create A records for TLD and all subdomains
    zone.fromString(`${this.domain} 21600 IN A ${this.host}`);
    zone.fromString(`*.${this.domain} 21600 IN A ${this.host}`);

    // Create TLSA from certificate
    const ssldir = join(configFolder, this.name, "tls", this.domain + "crt");
    const certfile = readFileSync(ssldir, "ascii");
    const cert = pem.fromPEM(certfile, "CERTIFICATE");
    const tlsarr = tlsa.create(cert, this.domain, "tcp", 443);

    zone.insert(tlsarr);

    // Wildcard the TLSA for subdomains
    const tlsaWild = tlsarr.clone();
    tlsaWild.name = `*.${this.domain}`;
    zone.insert(tlsaWild);

    // Create DNSKEY for ZSK
    let file = join(configFolder, this.name, "zsk", this.zskkey);
    zone.fromString(readFileSync(file).toString("ascii"));

    // Create DNSKEY for KSK
    file = join(configFolder, this.name, "ksk", this.kskkey);
    zone.fromString(readFileSync(file).toString("ascii"));

    // Sign DNSKEY RRset with KSK
    file = join(configFolder, this.name, "ksk", this.kskpriv);
    let string = readFileSync(file, "ascii");

    const [kalg, KSKpriv] = dnssec.decodePrivate(string);
    const KSKkey = dnssec.makeKey(this.domain, kalg, KSKpriv, ZONE | KSK);
    const DNSKEYrrset = this.server.zone.get(this.domain, types.DNSKEY);
    const RRSIGdnskey = dnssec.sign(KSKkey, KSKpriv, DNSKEYrrset);

    zone.insert(RRSIGdnskey);

    // Sign all other RRsets with ZSK
    file = join(configFolder, this.name, "zsk", this.zskpriv);
    string = readFileSync(file, "ascii");

    const [zalg, ZSKpriv] = dnssec.decodePrivate(string);
    const ZSKkey = dnssec.makeKey(this.domain, zalg, ZSKpriv, ZONE);

    for (const [, map] of zone.names) {
      for (const [, rrs] of map.rrs)
        zone.insert(dnssec.sign(ZSKkey, ZSKpriv, rrs));
    }

    // Add ZSK directly to zone to sign wildcards ad-hoc
    this.server.setZSKFromString(string);
  }
}

function generateBackupFilename(name) {
  const minutes = new Date().getMinutes();
  const seconds = new Date().getSeconds();
  const hours = new Date().getHours();

  return `${name}_backup_${new chronver().version}_${hours}${minutes}${seconds}`;
}

function indent(string, count) {
  const indent = " ";
  const regex = /^(?!\s*$)/gm;

  return string.replace(regex, indent.repeat(count));
  /// via https://github.com/sindresorhus/indent-string
}

function makeDirectorySyncRecursive(filename) {
  let filepath = filename.replace(/\\/g, "/");
  let root = "";

  if (filepath[0] === "/") {
    root = "/";
    filepath = filepath.slice(1);
  } else if (filepath[1] === ":") {
    root = filepath.slice(0, 3);
    filepath = filepath.slice(3);
  }

  const folders = filepath.split("/");

  const finalPath = folders.reduce((acc, folder) => {
    const folderPath = acc + folder + "/";

    if (!existsSync(folderPath))
      mkdirSync(folderPath);

    return folderPath;
  }, root);

  return finalPath;
}

function renderToString(source, data) {
  const template = handlebars.compile(source);
  const outputString = template(data);

  return outputString;
}

function toZone(records) {
  let text = "";

  for (const record of records) {
    text += record.toString();
    text += "\n\n";
  }

  return text;
  /// via https://github.com/pinheadmz/bns/blob/cname1/lib/wire.js
}

function writeFileSyncRecursive(filename, content) {
  let filepath = filename.replace(/\\/g, "/");
  let root = "";

  if (filepath[0] === "/") {
    root = "/";
    filepath = filepath.slice(1);
  } else if (filepath[1] === ":") {
    root = filepath.slice(0, 3);
    filepath = filepath.slice(3);
  }

  const folders = filepath.split("/").slice(0, -1);

  folders.reduce((acc, folder) => {
    const folderPath = acc + folder + "/";

    if (!existsSync(folderPath))
      mkdirSync(folderPath);

    return folderPath;
  }, root);

  writeFileSync(root + filepath, content);
  /// via https://gist.github.com/drodsou/de2ba6291aea67ffc5bc4b52d8c32abd
}

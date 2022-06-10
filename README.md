# dolo

> comprehensive TLD security



## intro

[Handshake](https://handshake.org) utilizes DNSSEC and DANE to secure sites. The problem with that is, it's quite complicated and confusing to setup. This repo aims to make it less painful to apply security to your own Handshake sites.

This project does a couple things:

- generates certificates
- generates keys
- generates a bind-compatible zone file
- generates a backup archive, in case you boom yourself

The bulk of the code here is from [@pinheadmz](https://github.com/pinheadmz)'s [handout](https://github.com/pinheadmz/handout) project, with niceties thrown in.



## install

```sh
npm i
```



## scripts

For a single name, you'll want to use the `generate-hnssec.mjs` script.

```sh
# if you want minimal output
node script/generate-hnssec.mjs --name <domain-name> --host <nameserver-ip>

# response
[dolo] Export finished:
       <name>/
```

```sh
# if you want verbose output
node script/generate-hnssec.mjs --name <domain-name> --host <nameserver-ip> --verbose

# response
[dolo] Generating TLS key and self-signed certificate…
       Key and certificate saved

[dolo] Generating DNSSEC keys…
       Writing new output.conf file…

       DS record for root zone:
       <domain-name>. 172800 IN DS 4672 8 2 7EAA99FA7278207485413C9A7200B8B9DC27314E1765D0D9BF959C53 7D6439A9 ; alg = RSASHA256 ; hash = SHA256

       GLUE4 record, Bob Wallet format:
       ns.<domain-name>. <nameserver-ip>

       DS record, Bob Wallet format:
       4672 8 2 7eaa99fa7278207485413c9a7200b8b9dc27314e1765d0d9bf959c537d6439a9

       All records, hsw-rpc sendupdate format:

       {
         "records": [
           {
             "address": "<nameserver-ip>",
             "ns": "ns.<domain-name>.",
             "type": "GLUE4"
           },
           {
             "algorithm": 8,
             "digest": "7eaa99fa7278207485413c9a7200b8b9dc27314e1765d0d9bf959c537d6439a9",
             "digestType": 2,
             "keyTag": 4672,
             "type": "DS"
           }
         ]
       }

       Keys and config saved

[dolo] Writing new <domain-name>.zone file…
       Zone file saved
       Backup archive created

[dolo] Export finished:
       <domain-name>/
```

If you want to generate certs, keys, configs, and backups for multiple names…say, a couple hundred, running the above script is not tenable. However, dolo's got you covered.

The `generate-many-hnssec.mjs` script makes several assumptions about your setup:
  - you are keeping track of your domain catalogue in your favorite spreadsheet app
  - you have a column with a header called "ascii," which is the punycode variant of the unicode name in each row
  - you've exported your spreadsheet as `catalogue.csv` and have placed it in the base of this project
  - you've run `npm run convert` to convert that CSV to JSON format and you haven't renamed the generated `catalogue.json`

```sh
# if you want minimal output…and not see anything for several minutes if your catalogue is massive
node script/generate-many-hnssec.mjs --host <nameserver-ip> --many
```

```sh
# if you want verbose output, and boy, it'll be a LOT
node script/generate-many-hnssec.mjs --host <nameserver-ip> --many --verbose
```



### output

Each domain name export will create a folder in `./output` and an archived backup of that folder in `./backup`. Running the above scripts **will overwrite** the `./output/<domain-name>` folder but **not** the archived backup. If you run this script several times, you'll want to keep the most recent backup file.

Directory structure:

```
/
└─ <domain-name>/
   ├─ ksk/
   │  ├─ K<domain-name>.+###+#####.private
   │  └─ K<domain-name>.+###+#####.key
   ├─ tls/
   │  ├─ <domain-name>.crt
   │  └─ <domain-name>.key
   ├─ zsk/
   │  ├─ K<domain-name>.+###+#####.private
   │  └─ K<domain-name>.+###+#####.key
   ├─ output.conf
   ├─ db.<domain-name>
   ├─ hsw-rpc_sendupdate.txt
   └─ README.md
```



### notes

- In the scripts examples:
  - replace `<domain-name>` with your domain name
  - replace `<nameserver-ip>` with the IP address of your nameserver



🤝

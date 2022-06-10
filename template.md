# {{domain}}/

> DNSSEC/DANE certs, keys, and config for {{domain}}



## instructions

These steps assumes you use Bob Wallet to manage your Handshake names and CoreDNS for your nameserver. Adjust as necessary if your setup differs.

### 1. Update domain on Handshake

In `records.conf`, you'll want the values under "Bob Wallet records:". Within Bob, highlight your name, select "Manage My Domain" and "Add Record," and punch in those aforementioned values.

### 2. Update domain on nameserver

On your nameserver, create the folder `/etc/bind/keys/{{domain}}/`. Upload the contents of `ksk/` and `zsk/` into the newly created folder.

Edit bind's options configuration to enable DNSSEC, if it's not already enabled.

```sh
# run this command…
nano /etc/bind/named.conf.options

# then, add these two lines within the file
dnssec-enable yes;
dnssec-validation auto;

# close and save this file
```

If `/etc/bind/db.{{domain}}` already exists, update it with the contents of `db.{{domain}}`. Update the serial and make sure you don't have multiple SOA records.

Otherwise, copy `db.{{domain}}` to `/etc/bind/`.

Next, you'll edit bind's local configuration.

```sh
# run this command…
nano /etc/bind/named.conf.local

# make sure paths exist or bind will complain
zone "{{domain}}" {
  type master;
  file "/etc/bind/db.{{domain}}";
  notify no;
  // DNSSEC
  key-directory "/etc/bind/keys/{{domain}}";
  auto-dnssec maintain;
  inline-signing yes;
};
```

We're almost done! Now it's time to sign the zone.

```sh
cd /etc/bind/keys/{{domain}}
dnssec-signzone -o {{domain}} -N INCREMENT -t -k {{ksk_filename}} /etc/bind/db.{{domain}} {{zsk_filename}}
```

Now reload the zones and whatnot:

```sh
# load new zones
rndc reconfig

# reload all zones
# if you have a lot of zones, this could affect server performance
rndc reload

# reload specific zone
rndc reload {{domain}}

# load keys for {{domain}}
rndc loadkeys {{domain}}

# confirm keys for {{domain}} are signed
rndc signing -list {{domain}}

# remember to resign every time zonefile changes, unless you have that happen automatically
```



## notes

- if bind is unable to sign zones:
  - `nano /etc/apparmor.d/usr.sbin.named`
  - change `/etc/bind/** r` to `/etc/bind/** rw`
- check bind status: `systemctl status bind9`
- reload bind: `systemctl reload bind9`
- MIGHT have to deal with permissions issues with `root` vs `bind` user/group



🤝

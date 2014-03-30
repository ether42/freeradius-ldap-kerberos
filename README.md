### Why this repository?

This repository provides the modified sources of Freeradius 3.1.0 (http://freeradius.org/) and MIT Kerberos 5 1.8.3 (http://web.mit.edu/kerberos/).

Many thanks to them for publishing great opensource projects.

It provides two new modules currently used at the school [42](http://www.42.fr):
  - rlm_ldap_forwarder: this module is simply a shortened version of the LDAP module to proxy the request to another RADIUS server if the user has been found in a LDAP directory (currently, it avoids our staff users to authenticate with their login and not something like login@domain, which is an Active Directory account, permitting us to have a NPS service providing a RADIUS server),
  - rlm_mschapv2_kerberos: this module is an updated version of the MSCHAP module in order to provide compatibility between a MIT Kerberos 5 database stored in a LDAP directory and the MSCHAPv2 protocole, inspired by [kcrap](http://www.spock.org/kcrap/), thanks to [fuhry.com](http://fuhry.com/blog/2012/01/01/mschapv2-against-mit-kerberos-yes-you-can/).

It is also not as clean as I wanted (no repository previously forked, patch of Kerberos library, ...) and this I why I'm publishing this "as is" (for the moment, I hope).

The installation instructions are Debian based and I'm assuming you have a bit of background references on Freeradius and MIT Kerberos.

The 'master' branch contains the modified sources, the 'sources' one provides the unaltered sources of the used projects.

### rlm_ldap_forwarder

To use this module, simply copy the configuration file of the original LDAP module and add it the 'realm' variable.
If the user is found in the LDAP directory, it will append @realm behind is login name.
If you also correctly set the suffix and proxy modules, the request will be automatically forwarded.

Example configuration:
```
ldap_forwarder forward_staff {
  force_check_config = yes
  #
  #  Note that this needs to match the name in the LDAP
  #  server certificate, if you're using ldaps.
  server = "dc.domain.example.org"
  # Realm for proxying the request
  realm = "domain.example.org"
  #  Port to connect on, defaults to 389. Setting this to
  #  636 will enable LDAPS if start_tls (see below) is not
  #  able to be used.
# port = 389
  # Administrator account for searching and possibly modifying.
  identity = "cn=admin,dc=example,dc=org"
  password = mypass
# Unless overridden in another section, the dn from which all
# searches will start from.
  base_dn = "dc=domain,dc=example,dc=org"
[...]

authorize {
  forward_staff
  suffix
[...]

realm domain.example.org {
  authhost = dc.domain.example.org
  accthost = dc.domain.example.org
  secret = somesecuresecret
}
```

### rlm_mschapv2_kerberos

To use this module, copy the configuration file of the original MSCHAP module and add the two following variables:
  - libkdb_path: the path to libkdb5.so (if you compile from this repository: /usr/local/lib/libkdb5.so),
  - libkdb_ldap_path: the path to libkdb_ldap.so (if you compile from this repository: /usr/local/lib/libkdb_ldap.so, beware the function krb5_ldap_read_startup_information() is not exported by default, but is exported in the modified sources).

To do simple, when the MSCHAPv2 authentification will fail, the module will search login@DEFAULT_KERBEROS_DOMAIN in the KDC LDAP backend, because you can retrieve a specific hash that can validate the authentication. It also check the expiration date of principals since we use it to deactivate accounts.
You have to enable the encryption method arcfour-hmac:normal on your KDC.

The module will retrieve a lot of informations from your krb5.conf:
  - ldap_conns_per_server,
  - ldap_kdc_dn,
  - ldap_service_password_file,
  - key_stash_file (you can generate this file if you don't have it),
  - ldap_servers (only the first one at the moment),
  - default domain...

In your server configuration, replace all mschap by mschapv2_kerberos, it won't affect the current usage.

Example:
```
mschapv2_kerberos {
  force_check_config = yes
  # libkdb path for dynamic linking
  libkdb_path = /usr/local/lib/libkdb5.so
  # libkdb_ldap path for dynamic linking
  libkdb_ldap_path = /usr/local/lib/libkdb_ldap.so
  #
  #  If you are using /etc/smbpasswd, see the 'passwd'
  #  module for an example of how to use /etc/smbpasswd
[...]

authenticate {
  #
  #  MSCHAP authentication.
  Auth-Type MS-CHAP {
    mschapv2_kerberos
  }
[...]
```

### Kerberos library modifications

Filedescriptor leak at each LDAP reconnection:
```
diff --git a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/kdb_ldap_conn.c b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/kdb_ldap_conn.c
index 82b0333..2bd513d 100644
--- a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/kdb_ldap_conn.c
+++ b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/kdb_ldap_conn.c
@@ -302,6 +302,7 @@ krb5_ldap_rebind(krb5_ldap_context *ldap_context,
 {
     krb5_ldap_server_handle     *handle = *ldap_server_handle;
 
+    ldap_unbind(handle->ldap_handle);
     if ((ldap_initialize(&handle->ldap_handle, handle->server_info->server_name) != LDAP_SUCCESS)
         || (krb5_ldap_bind(ldap_context, handle) != LDAP_SUCCESS))
         return krb5_ldap_request_next_handle_from_pool(ldap_context, ldap_server_handle);
```

Exported utility function in the .so Kerberos LDAP module:
```
diff --git a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/libkdb_ldap.exports b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/libkdb_ldap.exports
index 1ec9a39..74054c5 100644
--- a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/libkdb_ldap.exports
+++ b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/libkdb_ldap.exports
@@ -52,3 +52,4 @@ krb5_ldap_create
 krb5_ldap_set_mkey_list
 krb5_ldap_get_mkey_list
 krb5_ldap_invoke
+krb5_ldap_read_startup_information
```

Removed some leaks while searching the LDAP directory:
```
diff --git a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/ldap_misc.c b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/ldap_misc.c
index f549e23..fa4964e 100644
--- a/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/ldap_misc.c
+++ b/krb5/krb5-1.8.3/src/plugins/kdb/ldap/libkdb_ldap/ldap_misc.c
@@ -2055,8 +2055,13 @@ populate_krb5_db_entry(krb5_context context, krb5_ldap_context *ldap_context,
             for (i = 0; ber_tl_data[i] != NULL; i++) {
                 if ((st = berval2tl_data (ber_tl_data[i] , &ptr)) != 0)
                     break;
-                if ((st = krb5_dbe_update_tl_data(context, entry, ptr)) != 0)
+                if ((st = krb5_dbe_update_tl_data(context, entry, ptr)) != 0) {
+                    free(ptr->tl_data_contents);
+                    free(ptr);
                     break;
+                }
+                free(ptr->tl_data_contents);
+                free(ptr);
             }
             ldap_value_free_len (ber_tl_data);
             if (st != 0)
```

### Installation

```
apt-get install libldap-dev libssl-dev bison make gcc

Installation:
root@radius:~/radius/krb5/krb5-1.8.3/src# ./configure --with-ldap; make; make install;
root@radius:~/radius/radius/talloc-2.1.0# ./configure; make; make install;
root@radius:~/radius/radius/freeradius-server-3.1.0# ./configure; make; make install;
```

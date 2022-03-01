# This is because we need to download the latest image from Red Hat. Current
# implementation for doing ARG based FROM instructions require replacing
# the FROM with an already existing image (i.e. one we've previously built).
# This prevents us from retrieving the latest image from Red Hat.
#FROM registry.access.redhat.com/ubi8:8.5 as base
#ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_REGISTRY=docker.io
ARG BASE_IMAGE=redhat/ubi8
ARG BASE_TAG=8.5-226

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as base
# Using the offical RHEL image from docker hub
#FROM ${BASE_IMAGE}:${BASE_TAG} as base

COPY conf/scripts/base /dsop-fix/

COPY conf/certs/CA.pem /etc/pki/ca-trust/source/anchors/CA.pem
COPY conf/certs/WCF.pem /etc/pki/ca-trust/source/anchors/WCF.pem

COPY conf/banner/issue /etc/

# Be careful when adding packages because this will ultimately be built on a licensed RHEL host,
# which enables full RHEL repositories and could allow for installation of packages that would
# violate Red Hat license agreement when running the container on a non-RHEL licensed host.
# See the following link for more details:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/building_running_and_managing_containers/index/#add_software_to_a_running_ubi_container
RUN echo Update packages and install DISA STIG fixes && \
    # Disable all repositories (to limit RHEL host repositories) and only use official UBI repositories
    sed -i "s/enabled=1/enabled=0/" /etc/dnf/plugins/subscription-manager.conf && \
    # exclude upating the 'filesystem' package due to errors with rootless builds
    #     https://github.com/containers/buildah/issues/3309
    # exclude subscription-manager updates due to missing cloud-what dep in UBI repo
    echo "exclude=filesystem-*" >> /etc/dnf/dnf.conf && \
    chmod 644 /etc/issue /etc/pki/ca-trust/source/anchors/*.pem && \
    dnf repolist && \
    dnf update -y && \
    # install missing dependency for libpwquality
    dnf install -y cracklib-dicts nss && \
    echo "* hard maxlogins 10" > /etc/security/limits.d/maxlogins.conf && \
    # Do not use loops to iterate through shell scripts, this allows for scripts to fail
    # but the build to still be successful. Be explicit when executing scripts and ensure
    # that all scripts have "set -e" at the top of the bash file!
    #/dsop-fix/xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs.sh && \
    # no remediation script, no accounts have passwords
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed_sha512.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_difok.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_remember.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_banner_etc_issue.sh && \
    # rollback crypto policy to DEFAULT
    #/dsop-fix/xccdf_org.ssgproject.content_rule_configure_crypto_policy.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_configure_kerberos_crypto_policy.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_configure_openssl_crypto_policy.sh && \
    # usbguard not available in ubi
    #/dsop-fix/xccdf_org.ssgproject.content_rule_configure_usbguard_auditbackend.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_coredump_disable_backtraces.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_coredump_disable_storage.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_disable_users_coredumps.sh && \
    /dsop-fix/xccdf_org.ssgproject.content_rule_display_login_attempts.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_ensure_gpgcheck_local_packages.sh && \
    # /var/log/messages not used
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_file_groupowner_var_log_messages.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_file_groupownership_system_commands_dirs.sh && \
    # /var/log/messages not used
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_file_owner_var_log_messages.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_network_configure_name_resolution.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_no_empty_passwords.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_openssl_use_strong_entropy.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_package_crypto-policies_installed.sh && \
    #/dsop-fix/xccdf_org.ssgproject.content_rule_package_iptables_installed.sh && \
    # rng-tools not available in ubi
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_package_rng-tools_installed.sh && \
    # sudo not required by default in container
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_package_sudo_installed.sh && \
    # usbguard not available in ubi
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_package_usbguard_installed.sh && \
    # sudo not required by default in container
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_sudo_require_reauthentication.sh && \
    ##/dsop-fix/xccdf_org.ssgproject.content_rule_sudoers_validate_passwd.sh && \
    update-ca-trust && \
    update-ca-trust force-enable && \
    dnf clean all && \
    rm -rf /dsop-fix/ /var/cache/dnf/ /var/tmp/* /tmp/* /var/tmp/.???* /tmp/.???*

ENV container oci
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

CMD ["/bin/bash"]

FROM base as build

# NGINX SRC http://nginx.org/download/
ARG BASE_NGINX_SRC=1.21.6
# https://github.com/vision5/ngx_devel_kit/releases/tag/v0.3.1
ARG BASE_NGINX_DEVEL=0.3.1
# For set-misc-nginx-module https://github.com/openresty/set-misc-nginx-module


RUN dnf upgrade -y --nodocs && \
    dnf install -y --nodocs \
       gcc \
       make \
       openssl-devel \
       pcre-devel \
       perl \
       zlib-devel && \
    dnf clean all && \
    rm -rf /var/cache/dnf

COPY bin/nginx-${BASE_NGINX_SRC}.tar.gz bin/ngx_devel_kit-${BASE_NGINX_DEVEL}.tar.gz bin/set-misc-nginx-module.tar.gz /

RUN mkdir -p /usr/local/src/{nginx,ngx_devel_kit,set-misc-nginx-module} && \
    tar -zxf /nginx-1.21.6.tar.gz --strip-components=1 -C /usr/local/src/nginx && \
    tar -zxf /ngx_devel_kit-0.3.1.tar.gz --strip-components=1 -C /usr/local/src/ngx_devel_kit && \
    tar -zxf /set-misc-nginx-module.tar.gz --strip-components=1 -C /usr/local/src/set-misc-nginx-module && \
    cd /usr/local/src/nginx && \
    ./configure --prefix=/etc/nginx \
       --sbin-path=/usr/sbin/nginx \
       --modules-path=/usr/lib64/nginx/modules \
       --conf-path=/etc/nginx/nginx.conf \
       --error-log-path=/var/log/nginx/error.log \
       --http-log-path=/var/log/nginx/access.log \
       --pid-path=/var/run/nginx.pid \
       --lock-path=/var/run/nginx.lock \
       --http-client-body-temp-path=/var/cache/nginx/client_temp \
       --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
       --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
       --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
       --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
       --user=nginx \
       --group=nginx \
       --with-compat \
       --with-file-aio \
       --with-threads \
       --with-http_addition_module \
       --with-http_auth_request_module \
       --with-http_dav_module \
       --with-http_flv_module \
       --with-http_gunzip_module \
       --with-http_gzip_static_module \
       --with-http_mp4_module \
       --with-http_random_index_module \
       --with-http_realip_module \
       --with-http_secure_link_module \
       --with-http_slice_module \
       --with-http_ssl_module \
       --with-http_stub_status_module \
       --with-http_sub_module \
       --with-http_v2_module \
       --with-mail \
       --with-mail_ssl_module \
       --with-stream \
       --with-stream_realip_module \
       --with-stream_ssl_module \
       --with-stream_ssl_preread_module \
       --with-cc-opt='-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -fPIC' \
       --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie' \
       --add-dynamic-module=/usr/local/src/ngx_devel_kit \
       --add-dynamic-module=/usr/local/src/set-misc-nginx-module && \
     make && \
     make install

FROM base

# [nginx-stable]
# Latest RPMs can be found https://nginx.org/packages/rhel/8/x86_64/RPMS/
ARG BASE_NGINX=1.20.2-1

USER root

# for nginx signing key go to https://nginx.org/keys/nginx_signing.key
COPY conf/keys/nginx_signing.key bin/nginx-${BASE_NGINX}.rpm /tmp/
COPY conf/scripts/base-nginx/docker-entrypoint.sh /docker-entrypoint.sh
COPY conf/nginx.conf /etc/nginx/nginx.conf

RUN dnf upgrade -y && \
    rpm --import /tmp/nginx_signing.key && \
    dnf install -y /tmp/nginx-${BASE_NGINX}.rpm gettext && \
    rm /tmp/nginx-${BASE_NGINX}.rpm && \
    # Create necessary directories
    mkdir -p /docker-entrypoint.d/ && \
    mkdir -p /etc/nginx/templates && \
    # Fix nginx user permissions (user auto-created during rpm installation)
    touch /var/cache/nginx/nginx.pid && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx && \
    chown -R nginx:nginx /var/cache/nginx/nginx.pid && \
    chown -R nginx:nginx /docker-entrypoint.d && \
    # Cleanup installation
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    # Forward nginx logs to stdout and stderr
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

RUN cp -r /usr/share/nginx/html /etc/nginx && \
    rm /etc/nginx/conf.d/default.conf

COPY --from=build /usr/lib64/nginx/modules /usr/lib64/nginx/modules
COPY conf/scripts/base-nginx/10-listen-on-ipv6-by-default.sh conf/scripts/base-nginx/20-envsubst-on-templates.sh conf/scripts/base-nginx/30-tune-worker-processes.sh /docker-entrypoint.d/
RUN chown -R nginx:nginx /docker-entrypoint.d && \
    chmod o-w etc/nginx/nginx.conf && \
    chmod o-w docker-entrypoint.d/10-listen-on-ipv6-by-default.sh && \
    chmod o-w docker-entrypoint.d/30-tune-worker-processes.sh && \
    chmod o-w docker-entrypoint.d/20-envsubst-on-templates.sh && \
    chmod o-w docker-entrypoint.sh

USER nginx

EXPOSE 8080 8443

HEALTHCHECK --interval=10s --timeout=5s --start-period=1m --retries=5 \
   CMD curl -I -f --max-time 5 http://localhost:8080 || curl -fsk https://localhost:8443 || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]

/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "conf-parser.h"
#include "def.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "resolved-conf.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "resolved-dns-search-domain.h"
#include "resolved-dns-stub.h"
#include "dns-domain.h"
#include "socket-netlink.h"
#include "specifier.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_dns_stub_listener_mode, dns_stub_listener_mode, DnsStubListenerMode, "Failed to parse DNS stub listener mode setting");

static const char* const dns_stub_listener_mode_table[_DNS_STUB_LISTENER_MODE_MAX] = {
        [DNS_STUB_LISTENER_NO] = "no",
        [DNS_STUB_LISTENER_UDP] = "udp",
        [DNS_STUB_LISTENER_TCP] = "tcp",
        [DNS_STUB_LISTENER_YES] = "yes",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dns_stub_listener_mode, DnsStubListenerMode, DNS_STUB_LISTENER_YES);

static void dns_stub_listener_extra_hash_func(const DNSStubListenerExtra *a, struct siphash *state) {
        unsigned port;

        assert(a);

        siphash24_compress(&a->mode, sizeof(a->mode), state);
        siphash24_compress(&socket_address_family(&a->address), sizeof(a->address.type), state);
        siphash24_compress(&a->address, FAMILY_ADDRESS_SIZE(socket_address_family(&a->address)), state);

        (void) sockaddr_port(&a->address.sockaddr.sa, &port);
        siphash24_compress(&port, sizeof(port), state);
}

static int dns_stub_listener_extra_compare_func(const DNSStubListenerExtra *a, const DNSStubListenerExtra *b) {
        unsigned p, q;
        int r;

        assert(a);
        assert(b);

        r = CMP(a->mode, b->mode);
        if (r != 0)
                return r;

        r = CMP(socket_address_family(&a->address), socket_address_family(&b->address));
        if (r != 0)
                return r;

        r = memcmp(&a->address, &b->address, FAMILY_ADDRESS_SIZE(socket_address_family(&a->address)));
        if (r != 0)
                return r;

        (void) sockaddr_port(&a->address.sockaddr.sa, &p);
        (void) sockaddr_port(&b->address.sockaddr.sa, &q);

        return CMP(p, q);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                dns_stub_listener_extra_hash_ops,
                DNSStubListenerExtra,
                dns_stub_listener_extra_hash_func,
                dns_stub_listener_extra_compare_func,
                free);

static int manager_add_dns_server_by_string(Manager *m, DnsServerType type, const char *word) {
        _cleanup_free_ char *server_name = NULL;
        union in_addr_union address;
        int family, r, ifindex = 0;
        uint16_t port;
        DnsServer *s;

        assert(m);
        assert(word);

        r = in_addr_port_ifindex_name_from_string_auto(word, &family, &address, &port, &ifindex, &server_name);
        if (r < 0)
                return r;

        if (IN_SET(port, 53, 853))
                port = 0;

        /* Silently filter out 0.0.0.0 and 127.0.0.53 (our own stub DNS listener) */
        if (!dns_server_address_valid(family, &address))
                return 0;

        /* By default, the port number is determined with the transaction feature level.
         * See dns_transaction_port() and dns_server_port(). */
        if (IN_SET(port, 53, 853))
                port = 0;

        /* Filter out duplicates */
        s = dns_server_find(manager_get_first_dns_server(m, type), family, &address, port, ifindex, server_name);
        if (s) {
                /*
                 * Drop the marker. This is used to find the servers
                 * that ceased to exist, see
                 * manager_mark_dns_servers() and
                 * manager_flush_marked_dns_servers().
                 */
                dns_server_move_back_and_unmark(s);
                return 0;
        }

        return dns_server_new(m, NULL, type, NULL, family, &address, port, ifindex, server_name);
}

int manager_parse_dns_server_string_and_warn(Manager *m, DnsServerType type, const char *string) {
        int r;

        assert(m);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = manager_add_dns_server_by_string(m, type, word);
                if (r < 0)
                        log_warning_errno(r, "Failed to add DNS server address '%s', ignoring: %m", word);
        }

        return 0;
}

static int manager_add_search_domain_by_string(Manager *m, const char *domain) {
        DnsSearchDomain *d;
        bool route_only;
        int r;

        assert(m);
        assert(domain);

        route_only = *domain == '~';
        if (route_only)
                domain++;

        if (dns_name_is_root(domain) || streq(domain, "*")) {
                route_only = true;
                domain = ".";
        }

        r = dns_search_domain_find(m->search_domains, domain, &d);
        if (r < 0)
                return r;
        if (r > 0)
                dns_search_domain_move_back_and_unmark(d);
        else {
                r = dns_search_domain_new(m, &d, DNS_SEARCH_DOMAIN_SYSTEM, NULL, domain);
                if (r < 0)
                        return r;
        }

        d->route_only = route_only;
        return 0;
}

int manager_parse_search_domains_and_warn(Manager *m, const char *string) {
        int r;

        assert(m);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = manager_add_search_domain_by_string(m, word);
                if (r < 0)
                        log_warning_errno(r, "Failed to add search domain '%s', ignoring: %m", word);
        }

        return 0;
}

int config_parse_dns_servers(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);

        if (isempty(rvalue))
                /* Empty assignment means clear the list */
                dns_server_unlink_all(manager_get_first_dns_server(m, ltype));
        else {
                /* Otherwise, add to the list */
                r = manager_parse_dns_server_string_and_warn(m, ltype, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse DNS server string '%s'. Ignoring.", rvalue);
                        return 0;
                }
        }

        /* If we have a manual setting, then we stop reading
         * /etc/resolv.conf */
        if (ltype == DNS_SERVER_SYSTEM)
                m->read_resolv_conf = false;
        if (ltype == DNS_SERVER_FALLBACK)
                m->need_builtin_fallbacks = false;

        return 0;
}

int config_parse_search_domains(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Manager *m = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(m);

        if (isempty(rvalue))
                /* Empty assignment means clear the list */
                dns_search_domain_unlink_all(m->search_domains);
        else {
                /* Otherwise, add to the list */
                r = manager_parse_search_domains_and_warn(m, rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse search domains string '%s'. Ignoring.", rvalue);
                        return 0;
                }
        }

        /* If we have a manual setting, then we stop reading
         * /etc/resolv.conf */
        m->read_resolv_conf = false;

        return 0;
}

int config_parse_dnssd_service_name(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata) {
        static const Specifier specifier_table[] = {
                { 'm', specifier_machine_id,      NULL },
                { 'b', specifier_boot_id,         NULL },
                { 'H', specifier_host_name,       NULL },
                { 'v', specifier_kernel_release,  NULL },
                { 'a', specifier_architecture,    NULL },
                { 'o', specifier_os_id,           NULL },
                { 'w', specifier_os_version_id,   NULL },
                { 'B', specifier_os_build_id,     NULL },
                { 'W', specifier_os_variant_id,   NULL },
                {}
        };
        DnssdService *s = userdata;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        if (isempty(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Service instance name can't be empty. Ignoring.");
                return -EINVAL;
        }

        r = free_and_strdup(&s->name_template, rvalue);
        if (r < 0)
                return log_oom();

        r = specifier_printf(s->name_template, specifier_table, NULL, &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to replace specifiers: %m");

        if (!dns_service_name_is_valid(name)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Service instance name template renders to invalid name '%s'. Ignoring.", name);
                return -EINVAL;
        }

        return 0;
}

int config_parse_dnssd_service_type(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata) {
        DnssdService *s = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        if (isempty(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Service type can't be empty. Ignoring.");
                return -EINVAL;
        }

        if (!dnssd_srv_type_is_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Service type is invalid. Ignoring.");
                return -EINVAL;
        }

        r = free_and_strdup(&s->type, rvalue);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_dnssd_txt(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata) {
        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        DnssdService *s = userdata;
        DnsTxtItem *last = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(s);

        if (isempty(rvalue)) {
                /* Flush out collected items */
                s->txt_data_items = dnssd_txtdata_free_all(s->txt_data_items);
                return 0;
        }

        txt_data = new0(DnssdTxtData, 1);
        if (!txt_data)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL;
                _cleanup_free_ char *key = NULL;
                _cleanup_free_ char *value = NULL;
                _cleanup_free_ void *decoded = NULL;
                size_t length = 0;
                DnsTxtItem *i;
                int r;

                r = extract_first_word(&rvalue, &word, NULL,
                                       EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_CUNESCAPE_RELAX);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);

                r = split_pair(word, "=", &key, &value);
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EINVAL)
                        key = TAKE_PTR(word);

                if (!ascii_is_valid(key)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Invalid syntax, ignoring: %s", key);
                        return -EINVAL;
                }

                switch (ltype) {

                case DNS_TXT_ITEM_DATA:
                        if (value) {
                                r = unbase64mem(value, strlen(value), &decoded, &length);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_syntax(unit, LOG_ERR, filename, line, r,
                                                          "Invalid base64 encoding, ignoring: %s", value);
                        }

                        r = dnssd_txt_item_new_from_data(key, decoded, length, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                case DNS_TXT_ITEM_TEXT:
                        r = dnssd_txt_item_new_from_string(key, value, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                default:
                        assert_not_reached("Unknown type of Txt config");
                }

                LIST_INSERT_AFTER(items, txt_data->txt, last, i);
                last = i;
        }

        if (!LIST_IS_EMPTY(txt_data->txt)) {
                LIST_PREPEND(items, s->txt_data_items, txt_data);
                txt_data = NULL;
        }

        return 0;
}

int config_parse_dns_stub_listener_extra(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ DNSStubListenerExtra *udp = NULL, *tcp = NULL;
        _cleanup_free_ char *word = NULL;
        Manager *m = userdata;
        bool both = false;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                m->dns_extra_stub_listeners = ordered_set_free(m->dns_extra_stub_listeners);
                return 0;
        }

        p = rvalue;
        r = extract_first_word(&p, &word, ":", 0);
        if (r == -ENOMEM)
                return log_oom();
        if (r <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid DNSStubListenExtra='%s', ignoring assignment", rvalue);
                return 0;
        }

        /*  First look for udp/tcp. If not specified then turn both TCP and UDP */
        if (!STR_IN_SET(word, "tcp", "udp")) {
                both = true;
                p = rvalue;
        }

        if (streq(word, "tcp") || both) {
                r = dns_stub_extra_new(&tcp);
                if (r < 0)
                        return log_oom();

                tcp->mode = DNS_STUB_LISTENER_TCP;
        }

        if (streq(word, "udp") || both) {
                r = dns_stub_extra_new(&udp);
                if (r < 0)
                        return log_oom();

                udp->mode = DNS_STUB_LISTENER_UDP;
        }

        if (tcp) {
                r = socket_addr_port_from_string_auto(p, 53, &tcp->address);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address in DNSStubListenExtra='%s', ignoring", rvalue);
                        return 0;
                }
        }

        if (udp) {
                r = socket_addr_port_from_string_auto(p, 53, &udp->address);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address in DNSStubListenExtra='%s', ignoring", rvalue);
                        return 0;
                }
        }

        if (tcp) {
                r = ordered_set_ensure_put(&m->dns_extra_stub_listeners, &dns_stub_listener_extra_hash_ops, tcp);
                if (r < 0) {
                        if (r == -ENOMEM)
                                return log_oom();

                        log_warning_errno(r, "Failed to store TCP DNSStubListenExtra='%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

        if (udp) {
                r = ordered_set_ensure_put(&m->dns_extra_stub_listeners, &dns_stub_listener_extra_hash_ops, udp);
                if (r < 0) {
                        if (r == -ENOMEM)
                                return log_oom();

                        log_warning_errno(r, "Failed to store UDP DNSStubListenExtra='%s', ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

        TAKE_PTR(tcp);
        TAKE_PTR(udp);

        return 0;
}

int manager_parse_config_file(Manager *m) {
        int r;

        assert(m);

        r = config_parse_many_nulstr(
                        PKGSYSCONFDIR "/resolved.conf",
                        CONF_PATHS_NULSTR("systemd/resolved.conf.d"),
                        "Resolve\0",
                        config_item_perf_lookup, resolved_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m,
                        NULL);
        if (r < 0)
                return r;

        if (m->need_builtin_fallbacks) {
                r = manager_parse_dns_server_string_and_warn(m, DNS_SERVER_FALLBACK, DNS_SERVERS);
                if (r < 0)
                        return r;
        }

#if ! HAVE_GCRYPT
        if (m->dnssec_mode != DNSSEC_NO) {
                log_warning("DNSSEC option cannot be enabled or set to allow-downgrade when systemd-resolved is built without gcrypt support. Turning off DNSSEC support.");
                m->dnssec_mode = DNSSEC_NO;
        }
#endif

#if ! ENABLE_DNS_OVER_TLS
        if (m->dns_over_tls_mode != DNS_OVER_TLS_NO) {
                log_warning("DNS-over-TLS option cannot be enabled or set to opportunistic when systemd-resolved is built without DNS-over-TLS support. Turning off DNS-over-TLS support.");
                m->dns_over_tls_mode = DNS_OVER_TLS_NO;
        }
#endif
        return 0;

}

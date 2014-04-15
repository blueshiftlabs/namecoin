// Copyright (c) 2014 Justin Paupore
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef DKIMWRAP_H
#define DKIMWRAP_H

#include <stdbool.h>
#include <opendkim/dkim.h>
#include <vector>
#include <utility>
#include <string>

class dkim_stat;
class dkim_siginfo;
class dkim_context;
class dkim_lib;

class dkim_stat {
public:
    dkim_stat() : m_status(DKIM_STAT_OK) { }
    dkim_stat(DKIM_STAT status) : m_status(status) { }
    ~dkim_stat() { }

    operator const void*() const {
        return (m_status != DKIM_STAT_OK) ? this : NULL;
    }
    bool operator ==(const dkim_stat &other) const {
        return m_status == other.m_status;
    }
    bool operator !=(const dkim_stat &other) const {
        return !(*this == other);
    }
    
    const char *message() const;

private:
    DKIM_STAT m_status;
};

class dkim_siginfo {
public:
    dkim_siginfo() : m_ctx(NULL), m_sig(NULL) { }
    dkim_siginfo(DKIM *ctx, DKIM_SIGINFO *sig)
        : m_ctx(ctx), m_sig(sig) { }
    ~dkim_siginfo() { }

    dkim_stat get_identity(std::vector<unsigned char> &identity);
    bool is_header_signed(const char *hdr);
    dkim_stat is_body_fully_signed();
    
    // TODO: write strong-typed wrappers for these return types
    int get_dnssec();
    int get_error();
    
private:
    DKIM *m_ctx;
    DKIM_SIGINFO *m_sig;
};
    

class dkim_context {
public:
    dkim_context() : m_ctx(NULL) { }
    dkim_context(DKIM *ctx) : m_ctx(ctx) { }
    ~dkim_context();
    
    dkim_stat chunk(const unsigned char *data, size_t len);
    dkim_stat eom(bool *testkey = NULL);
    dkim_siginfo get_signature();

private:
    DKIM *m_ctx;
};
    
class dkim_lib {
public:
    dkim_lib();
    ~dkim_lib();

    operator const void*() const;
    dkim_stat verify(const char *id, dkim_context &ctx);

private:
    DKIM_LIB *m_lib;
};

bool parse_email_addr(const std::vector<unsigned char> &email, std::string &user, std::string &domain);

#endif

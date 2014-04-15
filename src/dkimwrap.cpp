#include "dkimwrap.h"
#include <opendkim/dkim.h>
#include <vector>
#include <string>
#include <cstring>

using namespace std;

const char *dkim_stat::message() const {
	switch (m_status) {
	case DKIM_STAT_OK:
		return "no error";
	case DKIM_STAT_BADSIG:
		return "bad signature";
	case DKIM_STAT_NOSIG:
		return "message not signed";
	case DKIM_STAT_NOKEY:
		return "DKIM key not available";
	case DKIM_STAT_CANTVRFY:
		return "Can't get key for verification";
	case DKIM_STAT_SYNTAX:
		return "Syntax error";
	case DKIM_STAT_NORESOURCE:
		return "Resource unavailable";
	case DKIM_STAT_INTERNAL:
		return "Internal error";
	case DKIM_STAT_REVOKED:
		return "Signing key revoked";
	case DKIM_STAT_INVALID:
		return "Invalid parameter";
	case DKIM_STAT_NOTIMPLEMENT:
		return "Not implemented";
	case DKIM_STAT_KEYFAIL:
		return "Key retrieval failed, try again later";
	case DKIM_STAT_CBREJECT:
		return "Rejected by callback";
	case DKIM_STAT_CBTRYAGAIN:
		return "Callback could not complete, try again later";
	case DKIM_STAT_CBERROR:
		return "Callback error";
	default:
		return "Unknown error";
	}
}

dkim_stat dkim_siginfo::get_identity(std::vector<unsigned char> &identity) {
	identity.clear();

	dkim_stat stat;
	do {
		identity.resize(identity.size() + 128);
		stat = dkim_sig_getidentity(m_ctx, m_sig, &identity[0], identity.size());
	} while (stat == DKIM_STAT_NORESOURCE);
	identity.resize(strlen((char*)&identity[0]));

	return stat;
}

bool dkim_siginfo::is_header_signed(const char *hdr) {
	return dkim_sig_hdrsigned(m_sig, (unsigned char *)hdr);
}

dkim_stat dkim_siginfo::is_body_fully_signed() {
	ssize_t msglen, canonlen;
	dkim_stat stat = dkim_sig_getcanonlen(m_ctx, m_sig, &msglen, &canonlen, NULL);
	if (stat) {
		return stat;
	} else {
		if (msglen == canonlen) {
			return DKIM_STAT_OK;
		} else {
			return DKIM_STAT_NOSIG;
		}
	}
}

int dkim_siginfo::get_dnssec() {
	return dkim_sig_getdnssec(m_sig);
}

int dkim_siginfo::get_error() {
	return dkim_sig_geterror(m_sig);
}

dkim_context::~dkim_context() {
	if (m_ctx) {
		dkim_free(m_ctx);
		m_ctx = NULL;
	}
}

dkim_stat dkim_context::chunk(const unsigned char *data, size_t len) {
	return dkim_chunk(m_ctx, const_cast<unsigned char *>(data), len);
}

dkim_stat dkim_context::eom(bool *testkey) {
	dkim_stat stat = chunk(NULL, 0);
	if (stat) {
		return stat;
	}

	return dkim_eom(m_ctx, testkey);
}

dkim_siginfo dkim_context::get_signature() {
	DKIM_SIGINFO *siginfo = dkim_getsignature(m_ctx);
	return dkim_siginfo(m_ctx, siginfo);
}

dkim_lib::dkim_lib() {
	m_lib = dkim_init(NULL, NULL);
}

dkim_lib::~dkim_lib() {
	if (m_lib) {
		dkim_close(m_lib);
		m_lib = NULL;
	}
}

dkim_lib::operator const void*() const {
	return (const void*)m_lib;
}

dkim_stat dkim_lib::verify(const char *id, dkim_context &ctx) {
	DKIM_STAT stat;
	DKIM *dkim = dkim_verify(m_lib, (const unsigned char *)id, NULL, &stat);
	if (dkim) {
		ctx.set_context(dkim);
		return dkim_stat();
	} else {
		return stat;
	}
}

bool parse_email_addr(const vector<unsigned char> &email, string &user, string &domain) {
	vector<unsigned char> email_copy(email);
	email_copy.push_back('\0');
	unsigned char *buf = &email_copy[0];
	unsigned char *user_p, *domain_p;
	if (dkim_mail_parse(buf, &user_p, &domain_p)) {
		return false;
	}

	user.assign((char*)user_p);
	domain.assign((char*)domain_p);

	return true;
}

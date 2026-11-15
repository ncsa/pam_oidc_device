/**
 * @file metadata.h
 * @brief Single source of truth for module identity and build metadata.
 *
 * Defines module name, version, description, and user-agent string macros.
 * Designed with simple `#define` syntax so Makefile and RPM spec files can
 * parse parameters using `sed`/`awk`.
 */

#ifndef METADATA_H
#define METADATA_H

#define MODULE_NAME "pam_oidc_device"
#define MODULE_VERSION "0.3.2"
#define MODULE_DESCRIPTION "PAM authentication module for OAuth 2.0 Device Authorization Grant"
#define MODULE_MAINTAINER "NCSA CyberInfrastructure <help@ncsa.illinois.edu>"
#define MODULE_USER_AGENT MODULE_NAME "/" MODULE_VERSION

#endif /* METADATA_H */

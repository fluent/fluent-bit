/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_AZURE_AUTH_H
#define FLB_AZURE_AUTH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>

/* Authentication types for Azure services */
typedef enum {
    FLB_AZURE_AUTH_KEY = 0,                       /* Shared Access Key */
    FLB_AZURE_AUTH_SAS,                           /* Shared Access Signature */
    FLB_AZURE_AUTH_SERVICE_PRINCIPAL,             /* Service Principal (Client ID + Secret) */
    FLB_AZURE_AUTH_MANAGED_IDENTITY_SYSTEM,       /* System-assigned Managed Identity */
    FLB_AZURE_AUTH_MANAGED_IDENTITY_USER,         /* User-assigned Managed Identity */
    FLB_AZURE_AUTH_WORKLOAD_IDENTITY              /* Workload Identity (Federated Token) */
} flb_azure_auth_type;

/* Azure Instance Metadata Service (IMDS) endpoint for Managed Identity */
#define FLB_AZURE_IMDS_HOST "169.254.169.254"
#define FLB_AZURE_IMDS_PORT "80"

/* Managed Identity authentication URL template */
#define FLB_AZURE_MSI_AUTH_URL_TEMPLATE \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01%s%s&resource=%s"

/* Microsoft Authentication Library (MSAL) authorization URL template */
#define FLB_AZURE_MSAL_AUTH_URL_TEMPLATE \
    "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

/* Azure Blob Storage resource identifier */
#define FLB_AZURE_BLOB_RESOURCE "https://storage.azure.com"

/* Azure Kusto resource identifier */
#define FLB_AZURE_KUSTO_RESOURCE "https://help.kusto.windows.net"

/* Default Workload Identity token file path */
#define FLB_AZURE_WORKLOAD_IDENTITY_TOKEN_FILE \
    "/var/run/secrets/azure/tokens/azure-identity-token"

/**
 * Get an OAuth2 access token using Azure Managed Identity (MSI)
 * 
 * This function retrieves an access token from the Azure Instance Metadata Service (IMDS)
 * for use with Azure services. Supports both system-assigned and user-assigned managed identities.
 * 
 * @param ctx OAuth2 context containing connection and token information
 * @return Access token string on success, NULL on failure
 */
char *flb_azure_msi_token_get(struct flb_oauth2 *ctx);

/**
 * Get an OAuth2 access token using Azure Workload Identity
 * 
 * This function exchanges a federated token (JWT) for an Azure AD access token
 * using the OAuth2 client credentials flow with client assertion.
 * 
 * @param ctx OAuth2 context for token management
 * @param token_file Path to the file containing the federated token
 * @param client_id Client ID of the Azure AD application
 * @param tenant_id Tenant ID of the Azure AD directory
 * @param resource Resource scope for the token (e.g., "https://storage.azure.com/")
 * @return 0 on success, -1 on failure
 */
int flb_azure_workload_identity_token_get(struct flb_oauth2 *ctx,
                                          const char *token_file,
                                          const char *client_id,
                                          const char *tenant_id,
                                          const char *resource);

/**
 * Build OAuth URL for Azure authentication
 * 
 * Creates the appropriate OAuth2 endpoint URL based on the authentication type.
 * For Managed Identity, uses IMDS endpoint. For Service Principal and Workload Identity,
 * uses Azure AD OAuth2 endpoint.
 * 
 * @param auth_type Type of authentication to use
 * @param tenant_id Azure AD tenant ID (required for Service Principal and Workload Identity)
 * @param client_id Client ID (optional, used for user-assigned managed identity)
 * @param resource Resource scope for the token (e.g., storage.azure.com)
 * @return Allocated SDS string with OAuth URL, or NULL on failure
 */
flb_sds_t flb_azure_auth_build_oauth_url(flb_azure_auth_type auth_type,
                                          const char *tenant_id,
                                          const char *client_id,
                                          const char *resource);

#endif /* FLB_AZURE_AUTH_H */

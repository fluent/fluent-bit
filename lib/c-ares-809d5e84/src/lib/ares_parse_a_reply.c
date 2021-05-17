
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2019 by Andrew Selivanov
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares_nameser.h"

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_a_reply(const unsigned char *abuf, int alen,
                       struct hostent **host,
                       struct ares_addrttl *addrttls, int *naddrttls)
{
  struct ares_addrinfo ai;
  struct ares_addrinfo_node *next;
  struct ares_addrinfo_cname *next_cname;
  char **aliases = NULL;
  char *question_hostname = NULL;
  struct hostent *hostent = NULL;
  struct in_addr *addrs = NULL;
  int naliases = 0, naddrs = 0, alias = 0, i;
  int cname_ttl = INT_MAX;
  int status;

  memset(&ai, 0, sizeof(ai));

  status = ares__parse_into_addrinfo2(abuf, alen, &question_hostname, &ai);
  if (status != ARES_SUCCESS)
    {
      ares_free(question_hostname);

      if (naddrttls)
        {
          *naddrttls = 0;
        }

      return status;
    }

  hostent = ares_malloc(sizeof(struct hostent));
  if (!hostent)
    {
      goto enomem;
    }

  next = ai.nodes;
  while (next)
    {
      if (next->ai_family == AF_INET)
        {
          ++naddrs;
        }
      next = next->ai_next;
    }

  next_cname = ai.cnames;
  while (next_cname)
    {
      if(next_cname->alias)
        ++naliases;
      next_cname = next_cname->next;
    }

  aliases = ares_malloc((naliases + 1) * sizeof(char *));
  if (!aliases)
    {
      goto enomem;
    }

  if (naliases)
    {
      next_cname = ai.cnames;
      while (next_cname)
        {
          if(next_cname->alias)
            aliases[alias++] = strdup(next_cname->alias);
          if(next_cname->ttl < cname_ttl)
            cname_ttl = next_cname->ttl;
          next_cname = next_cname->next;
        }
    }

  aliases[alias] = NULL;

  hostent->h_addr_list = ares_malloc((naddrs + 1) * sizeof(char *));
  if (!hostent->h_addr_list)
    {
      goto enomem;
    }

  for (i = 0; i < naddrs + 1; ++i)
    {
      hostent->h_addr_list[i] = NULL;
    }

  if (ai.cnames)
    {
      hostent->h_name = strdup(ai.cnames->name);
      ares_free(question_hostname);
    }
  else
    {
      hostent->h_name = question_hostname;
    }

  hostent->h_aliases = aliases;
  hostent->h_addrtype = AF_INET;
  hostent->h_length = sizeof(struct in_addr);

  if (naddrs)
    {
      addrs = ares_malloc(naddrs * sizeof(struct in_addr));
      if (!addrs)
        {
          goto enomem;
        }

      i = 0;
      next = ai.nodes;
      while (next)
        {
          if (next->ai_family == AF_INET)
            {
              hostent->h_addr_list[i] = (char *)&addrs[i];
              memcpy(hostent->h_addr_list[i],
                     &(CARES_INADDR_CAST(struct sockaddr_in *, next->ai_addr)->sin_addr),
                     sizeof(struct in_addr));
              if (naddrttls && i < *naddrttls)
                {
                  if (next->ai_ttl > cname_ttl)
                    addrttls[i].ttl = cname_ttl;
                  else
                    addrttls[i].ttl = next->ai_ttl;

                  memcpy(&addrttls[i].ipaddr,
                         &(CARES_INADDR_CAST(struct sockaddr_in *, next->ai_addr)->sin_addr),
                         sizeof(struct in_addr));
                }
              ++i;
            }
          next = next->ai_next;
        }
      if (i == 0)
        {
          ares_free(addrs);
        }
    }

  if (host)
    {
      *host = hostent;
    }
  else
    {
      ares_free_hostent(hostent);
    }

  if (naddrttls)
    {
      /* Truncated to at most *naddrttls entries */
      *naddrttls = (naddrs > *naddrttls)?*naddrttls:naddrs;
    }

  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  return ARES_SUCCESS;

enomem:
  ares_free(aliases);
  ares_free(hostent);
  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  ares_free(question_hostname);
  return ARES_ENOMEM;
}

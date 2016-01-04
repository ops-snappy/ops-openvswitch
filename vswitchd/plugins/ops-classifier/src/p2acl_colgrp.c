/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "p2acl_colgrp.h"
#include <stddef.h>
#include "vswitch-idl.h"

struct p2acl_colgrp p2acl_colgrps[NUM_P2ACL_COLGRPS];

#define ASSIGN_COLGRP(idx, type_arg, direction_arg, base)               \
    p2acl_colgrps[idx].type = type_arg;                                 \
    p2acl_colgrps[idx].direction = direction_arg;                       \
    p2acl_colgrps[idx].column_cur = &ovsrec_port_col_##base##_cur;      \
    p2acl_colgrps[idx].column_want = &ovsrec_port_col_##base##_want;    \
    p2acl_colgrps[idx].column_want_version = &ovsrec_port_col_##base##_want_version; \
    p2acl_colgrps[idx].column_want_status = &ovsrec_port_col_##base##_want_status; \
    p2acl_colgrps[idx].offset_cur = offsetof(struct ovsrec_port, base##_cur); \
    p2acl_colgrps[idx].offset_want = offsetof(struct ovsrec_port, base##_want); \
    p2acl_colgrps[idx].offset_want_version = offsetof(struct ovsrec_port, base##_want_version); \
    p2acl_colgrps[idx].offset_want_status = offsetof(struct ovsrec_port, base##_want_status); \
    p2acl_colgrps[idx].set_cur = ovsrec_port_set_##base##_cur;          \
    p2acl_colgrps[idx].set_want = ovsrec_port_set_##base##_want;        \
    p2acl_colgrps[idx].set_want_version = ovsrec_port_set_##base##_want_version; \
    p2acl_colgrps[idx].set_want_status = ovsrec_port_set_##base##_want_status

void
p2acl_colgroup_init(void) {
    ASSIGN_COLGRP(0, OPS_CLS_ACL_V4, OPS_CLS_DIRECTION_IN, aclv4_in);
}

/***** Getters *****/
#define MEMBER_AT_OFFSET(objptr, offset, type) \
    *(type*)(CONST_CAST(char*, (const char *)(objptr) + (offset)))

const struct ovsrec_acl*
p2acl_colgrp_get_cur(const struct p2acl_colgrp *colgrp,
                     const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, colgrp->offset_cur, const struct ovsrec_acl*);
}

const struct ovsrec_acl*
p2acl_colgrp_get_want(const struct p2acl_colgrp *colgrp,
                      const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, colgrp->offset_want, const struct ovsrec_acl*);
}

int64_t
p2acl_colgrp_get_want_version(const struct p2acl_colgrp *colgrp,
                              const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, colgrp->offset_want_version, int64_t);
}

const struct smap*
p2acl_colgrp_get_want_status(const struct p2acl_colgrp *colgrp,
                             const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, colgrp->offset_want_status,
                            const struct smap*);
}


/***** Setters *****/
void
p2acl_colgrp_set_cur(const struct p2acl_colgrp *colgrp,
                     const struct ovsrec_port *port,
                     const struct ovsrec_acl *cur)
{
    (*colgrp->set_cur)(port, cur);
}

void
p2acl_colgrp_set_want(const struct p2acl_colgrp *colgrp,
                      const struct ovsrec_port *port,
                      const struct ovsrec_acl *want)
{
    (*colgrp->set_want)(port, want);
}

void
p2acl_colgrp_set_want_version(const struct p2acl_colgrp *colgrp,
                              const struct ovsrec_port *port,
                              int64_t want_version)
{
    (*colgrp->set_want_version)(port, want_version);
}

void
p2acl_colgrp_set_want_status(const struct p2acl_colgrp *colgrp,
                             const struct ovsrec_port *port,
                             const struct smap *want_status)
{
    (*colgrp->set_want_status)(port, want_status);
}

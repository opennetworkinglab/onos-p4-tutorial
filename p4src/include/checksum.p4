/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CHECKSUM__
#define __CHECKSUM__

control FabricComputeChecksum(inout parsed_headers_t hdr,
                              inout fabric_metadata_t meta)
{
    apply {
        update_checksum(hdr.icmpv6.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_addr,
                hdr.ndp_option.type,
                hdr.ndp_option.length,
                hdr.ndp_option.value
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}

control FabricVerifyChecksum(inout parsed_headers_t hdr,
                             inout fabric_metadata_t meta)
{
    apply {}
}

#endif

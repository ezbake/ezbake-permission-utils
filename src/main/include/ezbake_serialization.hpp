/*   Copyright (C) 2013-2014 Computer Sciences Corporation
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
 * limitations under the License. */

#ifndef EZBAKE_SERIALIZATION_HPP
#define EZBAKE_SERIALIZATION_HPP

// Caused by base64.h included below
#pragma GCC diagnostic ignored "-Wconversion"

#include <cstdlib>
#include <cstring>

#include <stdexcept>

#include "boost/shared_ptr.hpp"

#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/protocol/TProtocol.h"
#include "thrift/transport/TBufferTransports.h"

extern "C" {
#include "base64.h"
}

namespace ezbake {
    template<typename THRIFT>
    void serialize_thrift(
            const THRIFT &native,
            uint8_t *&serialized_bytes,
            size_t &serialized_length) {
        using std::string;

        using boost::shared_ptr;

        using apache::thrift::protocol::TBinaryProtocol;
        using apache::thrift::protocol::TProtocol;
        using apache::thrift::transport::TMemoryBuffer;

        shared_ptr<TMemoryBuffer> transport_out{new TMemoryBuffer()};
        shared_ptr<TProtocol> protocol_out{new TBinaryProtocol(transport_out)};
        native.write(protocol_out.get());
        string serialized_as_str = transport_out->getBufferAsString();
        const char * const serialized_buffer = serialized_as_str.data();
        serialized_length = serialized_as_str.size();

        serialized_bytes = static_cast<uint8_t *>(malloc(serialized_length));
        memcpy(serialized_bytes, serialized_buffer, serialized_length);
    }

    template<typename THRIFT>
    char *serialize_thrift_base64(const THRIFT &native) {
        using std::runtime_error;

        uint8_t *serialized_binary = NULL;
        size_t serialized_length = 0;
        ezbake::serialize_thrift(native, serialized_binary, serialized_length);

        int base64_length = 0;
        char *serialized_base64 = base64(
                serialized_binary,
                static_cast<int>(serialized_length),
                &base64_length);

        free(serialized_binary);

        if (serialized_base64 == NULL) {
            throw runtime_error("Could not convert binary to base64");
        }

        return serialized_base64;
    }

    template<typename THRIFT>
    void deserialize_thrift(
            const uint8_t * const serialized_bytes,
            size_t serialized_length,
            THRIFT &native) {
        using boost::shared_ptr;

        using apache::thrift::protocol::TBinaryProtocol;
        using apache::thrift::protocol::TProtocol;
        using apache::thrift::transport::TMemoryBuffer;

        if (serialized_bytes == NULL) {
            throw std::invalid_argument("Serialized bytes cannot be null");
        }

        if (serialized_length == 0) {
            throw std::invalid_argument("Serialized length cannot be 0");
        }

        shared_ptr<TMemoryBuffer> transport_in{new TMemoryBuffer()};
        shared_ptr<TProtocol> protocol_in{new TBinaryProtocol(transport_in)};

        transport_in->resetBuffer(
                const_cast<uint8_t *>(serialized_bytes),
                static_cast<uint32_t>(serialized_length));

        native.read(protocol_in.get());
    }

    template<typename THRIFT>
    void deserialize_thrift(const std::string &serialized_base64, THRIFT &native) {
        deserialize_thrift(serialized_base64.c_str(), native);
    }

    template<typename THRIFT>
    void deserialize_thrift(
            const char * const serialized_base64,
            THRIFT &native) {
        int binary_length = 0;

        uint8_t *binary = unbase64(
                serialized_base64,
                static_cast<int>(strlen(serialized_base64)),
                &binary_length);

        if (binary == NULL) {
            throw std::invalid_argument("Could not convert base64 to binary");
        }

        deserialize_thrift(binary, static_cast<size_t>(binary_length), native);

        free(binary);
    }
}

#pragma GCC diagnostic warning "-Wconversion"

#endif

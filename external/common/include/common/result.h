#pragma once

#include <utility>
#include <optional>
#include <common/error.h>

namespace bcp::common {

    /** Wraps a return value with an error code.
     *
     *  For functions that return both a value and a success/failure state.
     *  Functions that yield no value return Error directly.
     */
    template<typename T>
    struct Result {
        Error error;
        std::optional<T> value;

        static Result<T> Success(T val) 
        {           
            return { Error::Ok, std::move(val) };    
        }

        static Result<T> Fail(Error err) 
        {
            return { err, std::nullopt };
        }

        T&& Take()
        {
            return std::move(*value);
        }

        bool isOk() const { return error == Error::Ok; }
        bool isErr() const { return error != Error::Ok; }
    };
}
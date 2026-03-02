-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
--
||| Foreign Function Interface Declarations
|||
||| This module declares all C-compatible functions that will be
||| implemented in the Zig FFI layer.
|||
||| All functions are declared here with type signatures and safety proofs.
||| Implementations live in ffi/zig/

module CLOUDGUARD_SERVER.ABI.Foreign

import CLOUDGUARD_SERVER.ABI.Types
import CLOUDGUARD_SERVER.ABI.Layout

%default total

--------------------------------------------------------------------------------
-- Library Lifecycle
--------------------------------------------------------------------------------

||| Initialize the library
||| Returns a handle to the library instance, or Nothing on failure
export
%foreign "C:cloudguard_server_init, libcloudguard_server"
prim__init : PrimIO Bits64

||| Safe wrapper for library initialization
export
init : IO (Maybe Handle)
init = do
  ptr <- primIO prim__init
  pure (createHandle ptr)

||| Clean up library resources
export
%foreign "C:cloudguard_server_free, libcloudguard_server"
prim__free : Bits64 -> PrimIO ()

||| Safe wrapper for cleanup
export
free : Handle -> IO ()
free h = primIO (prim__free (handlePtr h))

--------------------------------------------------------------------------------
-- Core Operations
--------------------------------------------------------------------------------

||| Example operation: process data
export
%foreign "C:cloudguard_server_process, libcloudguard_server"
prim__process : Bits64 -> Bits32 -> PrimIO Bits32

||| Safe wrapper with error handling
export
process : Handle -> Bits32 -> IO (Either Result Bits32)
process h input = do
  result <- primIO (prim__process (handlePtr h) input)
  pure $ case result of
    0 => Left Error
    n => Right n

--------------------------------------------------------------------------------
-- String Operations
--------------------------------------------------------------------------------

||| Convert C string to Idris String
export
%foreign "support:idris2_getString, libidris2_support"
prim__getString : Bits64 -> String

||| Free C string
export
%foreign "C:cloudguard_server_free_string, libcloudguard_server"
prim__freeString : Bits64 -> PrimIO ()

||| Get string result from library
export
%foreign "C:cloudguard_server_get_string, libcloudguard_server"
prim__getResult : Bits64 -> PrimIO Bits64

||| Safe string getter
export
getString : Handle -> IO (Maybe String)
getString h = do
  ptr <- primIO (prim__getResult (handlePtr h))
  if ptr == 0
    then pure Nothing
    else do
      let str = prim__getString ptr
      primIO (prim__freeString ptr)
      pure (Just str)

--------------------------------------------------------------------------------
-- Array/Buffer Operations
--------------------------------------------------------------------------------

||| Process array data
export
%foreign "C:cloudguard_server_process_array, libcloudguard_server"
prim__processArray : Bits64 -> Bits64 -> Bits32 -> PrimIO Bits32

||| Safe array processor
export
processArray : Handle -> (buffer : Bits64) -> (len : Bits32) -> IO (Either Result ())
processArray h buf len = do
  result <- primIO (prim__processArray (handlePtr h) buf len)
  pure $ case resultFromInt result of
    Just Ok => Right ()
    Just err => Left err
    Nothing => Left Error
  where
    resultFromInt : Bits32 -> Maybe Result
    resultFromInt 0 = Just Ok
    resultFromInt 1 = Just Error
    resultFromInt 2 = Just InvalidParam
    resultFromInt 3 = Just OutOfMemory
    resultFromInt 4 = Just NullPointer
    resultFromInt _ = Nothing

--------------------------------------------------------------------------------
-- Error Handling
--------------------------------------------------------------------------------

||| Get last error message
export
%foreign "C:cloudguard_server_last_error, libcloudguard_server"
prim__lastError : PrimIO Bits64

||| Retrieve last error as string
export
lastError : IO (Maybe String)
lastError = do
  ptr <- primIO prim__lastError
  if ptr == 0
    then pure Nothing
    else pure (Just (prim__getString ptr))

||| Get error description for result code
export
errorDescription : Result -> String
errorDescription Ok = "Success"
errorDescription Error = "Generic error"
errorDescription InvalidParam = "Invalid parameter"
errorDescription OutOfMemory = "Out of memory"
errorDescription NullPointer = "Null pointer"

--------------------------------------------------------------------------------
-- Version Information
--------------------------------------------------------------------------------

||| Get library version
export
%foreign "C:cloudguard_server_version, libcloudguard_server"
prim__version : PrimIO Bits64

||| Get version as string
export
version : IO String
version = do
  ptr <- primIO prim__version
  pure (prim__getString ptr)

||| Get library build info
export
%foreign "C:cloudguard_server_build_info, libcloudguard_server"
prim__buildInfo : PrimIO Bits64

||| Get build information
export
buildInfo : IO String
buildInfo = do
  ptr <- primIO prim__buildInfo
  pure (prim__getString ptr)

--------------------------------------------------------------------------------
-- Callback Support
--------------------------------------------------------------------------------

||| Callback function type (C ABI)
public export
Callback : Type
Callback = Bits64 -> Bits32 -> Bits32

||| Register a callback
export
%foreign "C:cloudguard_server_register_callback, libcloudguard_server"
prim__registerCallback : Bits64 -> AnyPtr -> PrimIO Bits32

-- TODO: Implement safe callback registration.
-- The callback must be wrapped via a proper FFI callback mechanism.
-- Do NOT use cast — it is banned per project safety standards.
-- See: https://idris2.readthedocs.io/en/latest/ffi/ffi.html#callbacks

--------------------------------------------------------------------------------
-- Utility Functions
--------------------------------------------------------------------------------

||| Check if library is initialized
export
%foreign "C:cloudguard_server_is_initialized, libcloudguard_server"
prim__isInitialized : Bits64 -> PrimIO Bits32

||| Check initialization status
export
isInitialized : Handle -> IO Bool
isInitialized h = do
  result <- primIO (prim__isInitialized (handlePtr h))
  pure (result /= 0)

/*
 * Copyright (C) 2024 Intel Corporation.
 * Copyright (C) 2024 University of Neuchatel, Switzerland.
 * 
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// Set the reference values below
byte[] mrEnclaveReference =
{
    0xDA, 0xE0, 0xDA, 0x2F, 0x8A, 0x53, 0xA0, 0xB4, 0x8F, 0x92, 0x6A, 0x3B, 0xC0, 0x48, 0xD6, 0xA9, 
    0x67, 0xD4, 0x7C, 0x86, 0x19, 0x86, 0x76, 0x6F, 0x8F, 0x5A, 0xB1, 0xC0, 0xA8, 0xD8, 0x8E, 0x44
};
byte[] mrSignerReference =
{
    0x83, 0xD7, 0x19, 0xE7, 0x7D, 0xEA, 0xCA, 0x14, 0x70, 0xF6, 0xBA, 0xF6, 0x2A, 0x4D, 0x77, 0x43, 
    0x03, 0xC8, 0x99, 0xDB, 0x69, 0x02, 0x0F, 0x9C, 0x70, 0xEE, 0x1D, 0xFC, 0x08, 0xC7, 0xCE, 0x9E
};
const ushort securityVersionReference = 0;
const ushort productIdReference = 0;
string nonce = "This is a sample.\0"; // Notice the \0 at the end, which is mandatory as C-strings are terminated with this char
string evidenceAsString = """{"type":"sgx_ecdsa","report_base64":"[..]","report_len":[..]}""";
string wasmFilePath = "../build/wasm-app/test.wasm";

// Parse and compute the claims
EvidenceJson? evidenceAsJson = JsonSerializer.Deserialize<EvidenceJson>(evidenceAsString, new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
});
Debug.Assert(evidenceAsJson != null, "The evidence cannot be parsed.");

byte[] wasmFileContent = await File.ReadAllBytesAsync(wasmFilePath);
byte[] nonceAsBytes = Encoding.UTF8.GetBytes(nonce);
byte[] computedUserData = await ComputeUserData(wasmFileContent, nonceAsBytes);
byte[] evidenceAsBytes = Convert.FromBase64String(evidenceAsJson.ReportBase64);
Evidence evidence = new(evidenceAsBytes);
int libRatsReturnValue = LibRats.VerifyEvidenceFromJson(evidenceAsString, await ComputeUserData(wasmFileContent, nonceAsBytes));

// Compare and display the results
Console.WriteLine($"User data, evidence: {BitConverter.ToString(evidence.UserData)}");
Console.WriteLine($"User Data, computed: {BitConverter.ToString(computedUserData)}");
Console.WriteLine($"Do the two user data match? {evidence.UserData.SequenceEqual(computedUserData)}");
Console.WriteLine($"MrEnclave: {BitConverter.ToString(evidence.MrEnclave)}");
Console.WriteLine($"Do the MrEnclave match? {mrEnclaveReference.SequenceEqual(evidence.MrEnclave)}");
Console.WriteLine($"MrSigner: {BitConverter.ToString(evidence.MrSigner)}");
Console.WriteLine($"Do the MrSigner match? {mrSignerReference.SequenceEqual(evidence.MrSigner)}");
Console.WriteLine($"Security Version: {evidence.SecurityVersion}, expected: {securityVersionReference}");
Console.WriteLine($"Product ID: {evidence.ProductId}, expected: {productIdReference}");
Console.WriteLine($"VerifyJsonUsingLibrats returned: {libRatsReturnValue:X}");

// Compute the user data as computed by WAMR
static async ValueTask<byte[]> ComputeUserData(byte[] wasmFileContent, byte[] nonce)
{
    using var sha256 = SHA256.Create();
    var wasmFileContentHash = sha256.ComputeHash(wasmFileContent);
            
    using MemoryStream stream = new();
    await stream.WriteAsync(wasmFileContentHash);
    await stream.WriteAsync(nonce);
    stream.Position = 0;    

    byte[] computedUserData = await sha256.ComputeHashAsync(stream);
    return computedUserData;
}

/// <summary>
/// The layout of the JSON is given by librats.
/// </summary>
class EvidenceJson
{
    public required string Type { get; init; }
    public required string ReportBase64 { get; init; }
    public required int ReportLen { get; init; }
}

/// <summary>
/// The start of the _report_body_t struct from Intel SGX is at offset 0x30.
/// </summary>
/// <remarks>
/// _report_body_t struct: https://github.com/intel/linux-sgx/blob/a1eeccba5a72b3b9b342569d2cc469ece106d3e9/common/inc/sgx_report.h#L93-L111
/// Attestation flow: https://www.intel.com/content/www/us/en/developer/articles/code-sample/software-guard-extensions-remote-attestation-end-to-end-example.html
/// </remarks>
class Evidence(byte[] evidenceAsBytes)
{
    public byte[] MrEnclave => evidenceAsBytes[0x70..0x90];
    public byte[] MrSigner => evidenceAsBytes[0xB0..0xD0];
    public ushort ProductId => BitConverter.ToUInt16(evidenceAsBytes.AsSpan(0x130, 2));
    public ushort SecurityVersion => BitConverter.ToUInt16(evidenceAsBytes.AsSpan(0x132, 2));
    public byte[] UserData => evidenceAsBytes[0x170..0x190];
}

static class LibRats
{
    /// <summary>
    /// Verifies the evidence using librats native function.
    /// </summary>
    /// <remarks>
    /// Original signature: int librats_verify_evidence_from_json(const char *json_string, const uint8_t *hash);
    /// </remarks>
    [DllImport("/usr/local/lib/librats/librats_lib.so", EntryPoint = "librats_verify_evidence_from_json")]
    public static extern int VerifyEvidenceFromJson(string json, byte[] hash);
}

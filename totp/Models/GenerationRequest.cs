using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Validation;

namespace roxy_totp.Models;

public class GenerationRequest
{
    public int Length {get; set;} = 160;

    public HashAlgorithm Algorithm {get; set;} = HashAlgorithm.SHA1;

    public int Digits {get; set;} = 6;
    
    public int PeriodSeconds {get; set;} = 30;

    public required string Label {get; set;}

    public string? Issuer {get; set;}
}

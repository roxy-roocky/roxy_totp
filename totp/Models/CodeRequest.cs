using System;

namespace roxy_totp.Models;

public class CodeRequest
{
    public int PeriodsTolerance {get; set;} = 0;
    public int PeriodSeconds {get; set;} = 30;
    public int Digits {get; set;} = 6;
    public required string Secret {get; set;}
    public HashAlgorithm Algorithm {get; set;} = HashAlgorithm.SHA1;
    public required long? Time {get; set;}
}

{ libssh2.inc } //# version: 2024.0117.2230
//#...
{$IFDEF FPC}
  {$ALIGN 8} //# For packed record
  {$MINENUMSIZE 1}
{$ELSE}
  {$IFDEF UNICODE}
    {$ALIGN 8} //# For packed record
    {$MINENUMSIZE 1}

    {$IFDEF CONDITIONALEXPRESSIONS}
      {$IF CompilerVersion >= 25.00} // XE4_UP
        {$ZEROBASEDSTRINGS OFF}

        {$IF CompilerVersion >= 33.00} // 10.3 Rio
          {$WARN UNSAFE_CAST OFF}                // W1048
          {$WARN EXPLICIT_STRING_CAST OFF}       // W1059
          {$WARN EXPLICIT_STRING_CAST_LOSS OFF}  // W1060
          {$WARN IMPLICIT_INTEGER_CAST_LOSS OFF} // W1071
          {$WARN IMPLICIT_CONVERSION_LOSS OFF}   // W1072
        {$IFEND}
      {$IFEND}
    {$ENDIF CONDITIONALEXPRESSIONS}

  {$ENDIF}
{$ENDIF}

{$undef allow_inline}
{$undef allow_delayed}
{$undef allow_hvdll}

{$IFDEF WIN32}
  {$IFNDEF CONDITIONALEXPRESSIONS}
    {$define allow_hvdll} { optional } //# alternative for: external '%dll_name%' name '%function_name%' delayed;
  {$ELSE   CONDITIONALEXPRESSIONS}
    {$IF CompilerVersion < 21.00}
      {$define allow_hvdll} { optional } //# alternative for: external '%dll_name%' name '%function_name%' delayed;
    {$ELSE}
      {$IFNDEF FPC}
        {$define allow_delayed} { optional }
        {$ifndef allow_delayed}
          {$define allow_hvdll} { optional }
        {$endif}
      {$ELSE}
        {$define allow_hvdll}   { optional }
      {$ENDIF}
    {$IFEND}
  {$ENDIF  CONDITIONALEXPRESSIONS}
{$ELSE}
  {$IFDEF WIN64}
    {$IFNDEF FPC}
      {$define allow_delayed} { optional } //#TODO: Crash for x86 dll. You need to check the bitness of the dll before load it.
      {$ifndef allow_delayed}
        {$define allow_hvdll} { optional }
      {$endif}
    {$ELSE  FPC}
      {$define allow_hvdll} { optional }
    {$ENDIF FPC}
  {$ENDIF WIN64}
{$ENDIF WIN32}

{$IFDEF FPC}
  {$define allow_inline} { optional }
{$ELSE}
  {$IFDEF CONDITIONALEXPRESSIONS}
    {$IF CompilerVersion >= 25.00}
      {$define allow_inline} { optional }
    {$IFEND}
  {$ENDIF}
{$ENDIF}

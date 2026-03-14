unit uApiClient;

interface

uses
  System.SysUtils, System.Classes, System.Net.HttpClient, System.Net.URLClient,
  System.JSON, System.Hash, IdSSLOpenSSL, IdHTTP;

type
  TApiClient = class
  private
    FHttpClient: THTTPClient;
    // CWE-798: Hardcoded API credentials
    const
      PAYMENT_API_KEY = 'pk_a8f3e2d1c4b5a6978869f0e1d2c3b4a5_prod_2024';
      EMAIL_SERVICE_KEY = 'em-key-abc123def456ghi789jkl012mno345pqr678stu901';
      SMS_AUTH_TOKEN = '32a1bcdef456789012345678abcdef90';
      NOTIFICATION_WEBHOOK = 'https://webhooks.internal.corp/notify/T9A3BX72M/B04QN8RSZ7H';
      DATABASE_CONNECTION_STRING = 'Server=prod-db.internal;Database=portal;User=admin;Password=Sup3r$ecret!Pr0d';
  public
    constructor Create;
    destructor Destroy; override;

    function ProcessPayment(const AAmount: Currency;
      const ACardNumber, AExpiry, ACVV: string): Boolean;
    procedure LogTransaction(const ACustomerID: Integer;
      const ACardNumber: string; const AAmount: Currency);
    function DeserializeConfig(const AJsonData: string): TJSONObject;
    function BuildApiUrl(const ABaseUrl, AUserInput: string): string;
    procedure SendNotification(const ARecipient, AMessage: string);
    function GenerateApiToken(const AUserID: Integer): string;
  end;

implementation

constructor TApiClient.Create;
begin
  inherited;
  FHttpClient := THTTPClient.Create;
end;

destructor TApiClient.Destroy;
begin
  FHttpClient.Free;
  inherited;
end;

// CWE-311: Missing Encryption of Sensitive Data
// CWE-522: Insufficiently Protected Credentials — card data sent over HTTP
function TApiClient.ProcessPayment(const AAmount: Currency;
  const ACardNumber, AExpiry, ACVV: string): Boolean;
var
  PostData: TStringList;
  Response: IHTTPResponse;
begin
  PostData := TStringList.Create;
  try
    PostData.Values['api_key'] := PAYMENT_API_KEY;
    PostData.Values['amount'] := CurrToStr(AAmount);
    PostData.Values['card_number'] := ACardNumber;
    PostData.Values['expiry'] := AExpiry;
    PostData.Values['cvv'] := ACVV;

    // CWE-319: Cleartext Transmission of Sensitive Information
    // Sending payment data over HTTP instead of HTTPS
    Response := FHttpClient.Post('http://api.payment-gateway.com/v1/charge',
      TStringStream.Create(PostData.Text));

    Result := Response.StatusCode = 200;
  finally
    PostData.Free;
  end;
end;

// CWE-532: Insertion of Sensitive Information into Log File
// CWE-312: Cleartext Storage of Sensitive Information
procedure TApiClient.LogTransaction(const ACustomerID: Integer;
  const ACardNumber: string; const AAmount: Currency);
var
  LogFile: TextFile;
  LogPath: string;
begin
  LogPath := 'C:\CustomerPortal\Logs\transactions.log';
  AssignFile(LogFile, LogPath);
  if FileExists(LogPath) then
    Append(LogFile)
  else
    Rewrite(LogFile);
  try
    // Full card number written to log file in plaintext
    WriteLn(LogFile, Format('[%s] Customer %d - Card: %s - Amount: %.2f',
      [DateTimeToStr(Now), ACustomerID, ACardNumber, AAmount]));
  finally
    CloseFile(LogFile);
  end;
end;

// CWE-502: Deserialization of Untrusted Data
function TApiClient.DeserializeConfig(const AJsonData: string): TJSONObject;
begin
  // Parsing untrusted JSON that could contain malicious payloads
  // In real Delphi, TJSONObject.ParseJSONValue with no validation
  Result := TJSONObject.ParseJSONValue(AJsonData) as TJSONObject;
end;

// CWE-918: Server-Side Request Forgery via URL manipulation
function TApiClient.BuildApiUrl(const ABaseUrl, AUserInput: string): string;
begin
  // User input directly concatenated into URL — SSRF and header injection
  Result := ABaseUrl + '/api/v1/data?filter=' + AUserInput;
end;

// CWE-79: XSS in notification message (if rendered in web context)
// CWE-93: CRLF Injection in HTTP header context
procedure TApiClient.SendNotification(const ARecipient, AMessage: string);
var
  Headers: TStringList;
begin
  Headers := TStringList.Create;
  try
    Headers.Values['Authorization'] := 'Bearer ' + EMAIL_SERVICE_KEY;
    Headers.Values['Content-Type'] := 'application/json';
    // ARecipient could contain CRLF characters for header injection
    Headers.Values['X-Custom-Recipient'] := ARecipient;

    FHttpClient.Post('https://api.sendgrid.com/v3/mail/send',
      TStringStream.Create(
        '{"to":"' + ARecipient + '","body":"' + AMessage + '"}'),
      nil);
  finally
    Headers.Free;
  end;
end;

// CWE-327: Weak cryptographic algorithm for token generation
// CWE-330: Predictable token values
function TApiClient.GenerateApiToken(const AUserID: Integer): string;
begin
  // MD5 of predictable values — easily brute-forced
  Result := THashMD5.GetHashString(
    IntToStr(AUserID) + DateTimeToStr(Now) + 'static_salt');
end;

end.

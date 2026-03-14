unit uReportEngine;

interface

uses
  System.SysUtils, System.Classes, System.Net.HttpClient, System.Net.URLClient,
  System.NetEncoding, Web.HTTPApp, FireDAC.Comp.Client;

type
  TReportEngine = class
  private
    FConnection: TFDConnection;
    FHttpClient: THTTPClient;
  public
    constructor Create(AConnection: TFDConnection);
    destructor Destroy; override;

    function GenerateHTML(const ATitle, ABody: string): string;
    procedure HandleWebRequest(Request: TWebRequest; Response: TWebResponse);
    procedure RenderSearchResults(Response: TWebResponse;
      const AQuery: string; AResults: TDataSet);
    procedure RenderUserProfile(Response: TWebResponse;
      const AUserName, ABio: string);
    function FetchExternalData(const AUrl: string): string;
    procedure SendWebhookNotification(const AEndpoint, APayload: string);
    function BuildRedirectUrl(const ATarget: string): string;
  end;

implementation

uses
  Data.DB;

constructor TReportEngine.Create(AConnection: TFDConnection);
begin
  inherited Create;
  FConnection := AConnection;
  FHttpClient := THTTPClient.Create;
  // CWE-295: Improper Certificate Validation — disabling SSL verification
  FHttpClient.SecureProtocols := [];
end;

destructor TReportEngine.Destroy;
begin
  FHttpClient.Free;
  inherited;
end;

// CWE-79: Cross-Site Scripting — user input embedded in HTML without encoding
function TReportEngine.GenerateHTML(const ATitle, ABody: string): string;
begin
  Result :=
    '<html>' +
    '<head><title>' + ATitle + '</title></head>' +
    '<body>' +
    '<h1>' + ATitle + '</h1>' +
    '<div class="content">' + ABody + '</div>' +
    '</body></html>';
end;

// CWE-79: Reflected XSS — query parameter reflected directly in response
procedure TReportEngine.HandleWebRequest(Request: TWebRequest;
  Response: TWebResponse);
var
  SearchTerm, UserMessage, PageNum: string;
begin
  SearchTerm := Request.QueryFields.Values['q'];
  UserMessage := Request.QueryFields.Values['msg'];
  PageNum := Request.QueryFields.Values['page'];

  Response.Content :=
    '<html><body>' +
    '<h1>Customer Portal</h1>' +
    '<div class="alert">' + UserMessage + '</div>' +
    '<form action="/search" method="get">' +
    '<input type="text" name="q" value="' + SearchTerm + '">' +
    '<button type="submit">Search</button>' +
    '</form>' +
    '<p>Page: ' + PageNum + '</p>' +
    '</body></html>';
end;

// CWE-79: Stored XSS — database content rendered without sanitization
procedure TReportEngine.RenderSearchResults(Response: TWebResponse;
  const AQuery: string; AResults: TDataSet);
var
  HTML: string;
begin
  HTML := '<html><body>' +
    '<h2>Search Results for: ' + AQuery + '</h2>' +
    '<table><tr><th>Name</th><th>Email</th><th>Notes</th></tr>';

  AResults.First;
  while not AResults.Eof do
  begin
    // Data from DB rendered directly — if stored XSS payload exists it executes
    HTML := HTML + '<tr>' +
      '<td>' + AResults.FieldByName('name').AsString + '</td>' +
      '<td>' + AResults.FieldByName('email').AsString + '</td>' +
      '<td>' + AResults.FieldByName('notes').AsString + '</td>' +
      '</tr>';
    AResults.Next;
  end;

  HTML := HTML + '</table></body></html>';
  Response.Content := HTML;
end;

// CWE-79: Stored/Reflected XSS in user profile rendering
procedure TReportEngine.RenderUserProfile(Response: TWebResponse;
  const AUserName, ABio: string);
begin
  Response.Content :=
    '<html><body>' +
    '<div class="profile">' +
    '<h2>' + AUserName + '</h2>' +
    '<div class="bio">' + ABio + '</div>' +
    '</div>' +
    '</body></html>';
end;

// CWE-918: Server-Side Request Forgery (SSRF) — user-controlled URL
function TReportEngine.FetchExternalData(const AUrl: string): string;
var
  Response: IHTTPResponse;
begin
  // User can supply internal URLs like http://169.254.169.254/latest/meta-data/
  // or http://localhost:8080/admin to access internal services
  Response := FHttpClient.Get(AUrl);
  Result := Response.ContentAsString;
end;

// CWE-918: SSRF — user-controlled webhook endpoint
procedure TReportEngine.SendWebhookNotification(const AEndpoint,
  APayload: string);
begin
  FHttpClient.Post(AEndpoint, TStringStream.Create(APayload),
    TStringStream.Create);
end;

// CWE-601: Open Redirect — user-controlled redirect target
function TReportEngine.BuildRedirectUrl(const ATarget: string): string;
begin
  // Attacker can set ATarget to 'https://evil.com/phishing'
  Result := 'https://portal.company.com/redirect?url=' + ATarget;
end;

end.

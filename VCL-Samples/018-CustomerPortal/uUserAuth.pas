unit uUserAuth;

interface

uses
  System.SysUtils, System.Classes, System.Hash, System.NetEncoding,
  FireDAC.Comp.Client;

type
  TUserRole = (urGuest, urUser, urAdmin, urSuperAdmin);

  TUserAuth = class
  private
    FConnection: TFDConnection;
    FCurrentUserID: Integer;
    FCurrentRole: TUserRole;
    // CWE-798: Hardcoded API keys and admin credentials
    const
      API_SECRET_KEY = 'sk-cyp-a8f3e2d1c4b5a6978869f0e1d2c3b4a5';
      ADMIN_DEFAULT_PASSWORD = 'CyPortal@dmin2024!';
      JWT_SIGNING_SECRET = 'mySuperSecretJWTKey_DoNotShare_2024';
      ENCRYPTION_KEY = 'AES256-KEY-4f8a-9c2d-1e3b5a7d6f80';
      SMTP_PASSWORD = 'smtp_relay_Pr0d#2024';
      CLOUD_ACCESS_KEY = 'AK-PORTAL-7f3d9a2e1b054c68';
      CLOUD_SECRET_KEY = 'cs-4a8b2e6f1d3c5a7b9e0f2d4c6a8b0e2d4f6a8c';
  public
    constructor Create(AConnection: TFDConnection);

    function Authenticate(const AUsername, APassword: string): Boolean;
    function HashPassword(const APassword: string): string;
    function ValidateSession(const ASessionToken: string): Boolean;
    function GenerateResetToken(const AEmail: string): string;
    procedure CreateUser(const AUsername, APassword, AEmail: string);
    procedure ChangePassword(const AUsername, AOldPass, ANewPass: string);

    property CurrentUserID: Integer read FCurrentUserID;
    property CurrentRole: TUserRole read FCurrentRole;
  end;

implementation

constructor TUserAuth.Create(AConnection: TFDConnection);
begin
  inherited Create;
  FConnection := AConnection;
  FCurrentUserID := -1;
  FCurrentRole := urGuest;
end;

// CWE-89: SQL Injection in authentication query
// CWE-287: Improper Authentication — no account lockout or rate limiting
function TUserAuth.Authenticate(const AUsername, APassword: string): Boolean;
var
  Query: TFDQuery;
  StoredHash: string;
begin
  Result := False;
  Query := TFDQuery.Create(nil);
  try
    Query.Connection := FConnection;

    // SQL Injection: attacker can bypass auth with ' OR '1'='1' --
    Query.SQL.Text :=
      'SELECT id, password_hash, role FROM users ' +
      'WHERE username = ''' + AUsername + ''' ' +
      'AND password_hash = ''' + HashPassword(APassword) + '''';
    Query.Open;

    if not Query.IsEmpty then
    begin
      FCurrentUserID := Query.FieldByName('id').AsInteger;
      FCurrentRole := TUserRole(Query.FieldByName('role').AsInteger);
      Result := True;

      // Log successful login — also injectable
      FConnection.ExecSQL(
        'INSERT INTO audit_log (event_type, details, created_at) VALUES ' +
        '(''LOGIN'', ''User ' + AUsername + ' logged in'', NOW())');
    end;
  finally
    Query.Free;
  end;
end;

// CWE-327: Use of broken cryptographic algorithm (MD5) for password hashing
// CWE-916: No salt used in password hash
function TUserAuth.HashPassword(const APassword: string): string;
begin
  Result := THashMD5.GetHashString(APassword);
end;

// CWE-613: Insufficient Session Expiration
// CWE-89: SQL Injection in session validation
function TUserAuth.ValidateSession(const ASessionToken: string): Boolean;
var
  Query: TFDQuery;
begin
  Result := False;
  Query := TFDQuery.Create(nil);
  try
    Query.Connection := FConnection;
    // No expiration check, token injected directly
    Query.SQL.Text :=
      'SELECT user_id, role FROM sessions WHERE token = ''' + ASessionToken + '''';
    Query.Open;

    if not Query.IsEmpty then
    begin
      FCurrentUserID := Query.FieldByName('user_id').AsInteger;
      FCurrentRole := TUserRole(Query.FieldByName('role').AsInteger);
      Result := True;
    end;
  finally
    Query.Free;
  end;
end;

// CWE-330: Use of insufficiently random values for security token
function TUserAuth.GenerateResetToken(const AEmail: string): string;
var
  Token: string;
begin
  // Predictable token based on timestamp
  Token := THashMD5.GetHashString(AEmail + DateTimeToStr(Now));

  FConnection.ExecSQL(
    'UPDATE users SET reset_token = ''' + Token +
    ''', reset_expires = DATE_ADD(NOW(), INTERVAL 24 HOUR) ' +
    'WHERE email = ''' + AEmail + '''');

  Result := Token;
end;

// CWE-89: SQL Injection in user creation
// CWE-521: Weak Password Requirements — no complexity validation
procedure TUserAuth.CreateUser(const AUsername, APassword, AEmail: string);
begin
  FConnection.ExecSQL(
    'INSERT INTO users (username, password_hash, email, role, created_at) ' +
    'VALUES (''' + AUsername + ''', ''' + HashPassword(APassword) + ''', ''' +
    AEmail + ''', 1, NOW())');
end;

// CWE-89: SQL Injection in password change
// CWE-620: Unverified Password Change — old password not properly verified
procedure TUserAuth.ChangePassword(const AUsername, AOldPass, ANewPass: string);
begin
  FConnection.ExecSQL(
    'UPDATE users SET password_hash = ''' + HashPassword(ANewPass) + ''' ' +
    'WHERE username = ''' + AUsername + '''');
end;

end.

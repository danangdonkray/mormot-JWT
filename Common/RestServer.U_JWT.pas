unit RestServer.U_JWT;

interface
uses
  Windows,
  SysUtils,
  Classes,
  SynZip,
  SynLZ,
  SynCrtSock,
  {$ifndef NOHTTPCLIENTWEBSOCKETS}
  SynBidirSock, // for WebSockets
  {$endif}
  SynCrypto,    // for hcSynShaAes
  SynCommons,
  SynLog,
  mORMot,
  mORMotHttpClient;

const
  JWTDefaultTimeout: integer = 10;
  JWTDefaultRefreshTimeOut : Cardinal = (SecsPerDay div 3 + UnixDateDelta);

type
  TSQLRestRoutingREST_JWT = class(TSQLRestRoutingREST)
  protected
    procedure AuthenticationFailed(Reason: TNotifyAuthenticationFailedReason); override;
  end;

  TSQLRestServerAuthenticationJWT = class(TSQLRestServerAuthenticationHttpBasic)
  protected
    procedure SessionCreate(Ctxt: TSQLRestServerURIContext; var User: TSQLAuthUser); override;
    procedure AuthenticationFailed(Ctxt: TSQLRestServerURIContext; Reason: TNotifyAuthenticationFailedReason);

    class function ClientGetSessionKey(Sender: TSQLRestClientURI;
      User: TSQLAuthUser; const aNameValueParameters: array of const): RawUTF8; override;
  public
    constructor Create(aServer: TSQLRestServer); override;

    function RetrieveSession(Ctxt: TSQLRestServerURIContext): TAuthSession; override;
    function Auth(Ctxt: TSQLRestServerURIContext): boolean; override;

    class function ClientSetUser(Sender: TSQLRestClientURI; const aUserName, aPassword: RawUTF8;
      aPasswordKind: TSQLRestServerAuthenticationClientSetUserPassword=passClear;
      const aHashSalt: RawUTF8=''; aHashRound: integer=20000): boolean; override;
  end;

  TSQLRestServerAuthenticationJWTClass = class of TSQLRestServerAuthenticationJWT;

  TSQLHttpClientJWT = class(TSQLHttpClientRequest)
  private
    fJWT: RawUTF8;
  protected
    procedure InternalSetClass; override;
    function InternalRequest(const url, method: RawUTF8;
      var Header, Data, DataType: RawUTF8): Int64Rec; override;
  public
    function SetUser(const aUserName, aPassword: RawUTF8;
      aHashedPassword: Boolean=false): boolean; reintroduce;
    property jwt : RawUTF8 read fJWT write fJWT;
  end;

function getAlgo(const Value : RawUTF8) : TSignAlgo;

implementation

function HeaderOnce(const Head : RawUTF8; upper: PAnsiChar): RawUTF8;
  {$ifdef HASINLINE}inline;{$endif}
begin
  if (Head <> '') then
    result := FindIniNameValue(pointer(Head),upper)
  else result := '';
end;

function getAlgo(
  const Value: RawUTF8): TSignAlgo;
var i : TSignAlgo;
begin
  Result := saSha256;
  for i := low(JWT_TEXT) to High(JWT_TEXT) do
    if SameTextU(Value, JWT_TEXT[i]) then begin
      result := i;
      break;
    end;
end;

{ TSQLRestRoutingREST_JWT }

procedure TSQLRestRoutingREST_JWT.AuthenticationFailed(
  Reason: TNotifyAuthenticationFailedReason);
begin
  inherited AuthenticationFailed(Reason);
end;

{ TSQLRestServerAuthenticationJWT }

function TSQLRestServerAuthenticationJWT.Auth(
  Ctxt: TSQLRestServerURIContext): boolean;
var aUserName, aPassWord : RawUTF8;
    User: TSQLAuthUser;
begin
  result := False;
  if AuthSessionRelease(Ctxt) then
    exit;

  if not Assigned(fServer.JWTForUnauthenticatedRequest) then begin
      AuthenticationFailed(Ctxt, afJWTRequired);
    Exit;
  end;

  aUserName := Ctxt.InputUTF8OrVoid['UserName'];
  aPassWord := Ctxt.InputUTF8OrVoid['Password'];

  if (aUserName<>'') and (length(aPassWord)>0) then begin
    User := GetUser(Ctxt,aUserName);
    try
      result := User<>nil;
      if result then begin
        if CheckPassword(Ctxt, User, aPassWord) then
          SessionCreate(Ctxt, User)
        else AuthenticationFailed(Ctxt, afInvalidPassword);
      end
      else AuthenticationFailed(Ctxt, afUnknownUser);
    finally
      if result then User.Free;
    end;
  end
  else AuthenticationFailed(Ctxt, afUnknownUser);
end;

procedure TSQLRestServerAuthenticationJWT.AuthenticationFailed(Ctxt: TSQLRestServerURIContext;
  Reason: TNotifyAuthenticationFailedReason);
begin
  if Ctxt is TSQLRestRoutingREST_JWT then
    TSQLRestRoutingREST_JWT(Ctxt).AuthenticationFailed(Reason);
end;

class function TSQLRestServerAuthenticationJWT.ClientGetSessionKey(
  Sender: TSQLRestClientURI; User: TSQLAuthUser;
  const aNameValueParameters: array of const): RawUTF8;
var resp: RawUTF8;
    values: array[0..9] of TValuePUTF8Char;
    a: integer;
    algo: TSQLRestServerAuthenticationSignedURIAlgo absolute a;
begin
  Result := '';
  if (Sender.CallBackGet('Auth',aNameValueParameters,resp)=HTTP_SUCCESS) then
    result := resp;
end;

class function TSQLRestServerAuthenticationJWT.ClientSetUser(
  Sender: TSQLRestClientURI; const aUserName, aPassword: RawUTF8;
  aPasswordKind: TSQLRestServerAuthenticationClientSetUserPassword;
  const aHashSalt: RawUTF8; aHashRound: integer): boolean;
var res: RawUTF8;
    U: TSQLAuthUser;
    vTmp : Variant;
begin
  result := false;
  if (aUserName='') or (Sender=nil) then
    exit;
  if not Sender.InheritsFrom(TSQLHttpClientJWT) then
    exit;

  if aPasswordKind<>passClear then
    raise ESecurityException.CreateUTF8('%.ClientSetUser(%) expects passClear',
      [self,Sender]);
  Sender.SessionClose; // ensure Sender.SessionUser=nil
  try // inherited ClientSetUser() won't fit with Auth() method below
    ClientSetUserHttpOnly(Sender,aUserName,aPassword);
    TSQLHttpClientJWT(Sender).jwt := '';
    U := TSQLAuthUser(Sender.Model.GetTableInherited(TSQLAuthUser).Create);
    try
      U.LogonName := trim(aUserName);
      res := ClientGetSessionKey(Sender,U,['Username', aUserName, 'password', aPassword]);

      if res<>'' then begin
        vTmp := _JsonFast(res);
        if DocVariantType.IsOfType(vTmp) then begin
          result := TSQLHttpClientJWT(Sender).SessionCreate(self,U,TDocvariantData(vTmp).U['result']);
          if result then

            TSQLHttpClientJWT(Sender).jwt := TDocvariantData(vTmp).U['jwt'];
        end;
      end;
    finally
      U.Free;
    end;
  finally
    if not result then begin
      // on error, reverse all values
      TSQLHttpClientJWT(Sender).jwt := '';
    end;
    if Assigned(Sender.OnSetUser) then
      Sender.OnSetUser(Sender); // always notify of user change, even if failed
  end;
end;

constructor TSQLRestServerAuthenticationJWT.Create(aServer: TSQLRestServer);
begin
  inherited Create(aServer);
end;

function TSQLRestServerAuthenticationJWT.RetrieveSession(
  Ctxt: TSQLRestServerURIContext): TAuthSession;
var aUserName : RawUTF8;
    User: TSQLAuthUser;
    i : Integer;
    tmpIdsession : Cardinal;
    pSession : PDocVariantData;
    vSessionPrivateSalt : RawUTF8;
begin
  result := inherited RetrieveSession(Ctxt);

  if result <> nil then
    Exit;

  if not Assigned(fServer.JWTForUnauthenticatedRequest) then
    Exit;

  vSessionPrivateSalt := '';
  if Ctxt.AuthenticationBearerToken <> '' then
    if Ctxt.AuthenticationCheck(fServer.JWTForUnauthenticatedRequest) then begin
      aUserName := Ctxt.JWTContent.reg[jrcIssuer];
      User := GetUser(Ctxt,aUserName);
      try
        if User <> nil then begin
          if Ctxt.Server.Sessions <> nil then begin
            if Ctxt.JWTContent.data.GetValueIndex('sessionkey') >= 0 then
              vSessionPrivateSalt := Ctxt.JWTContent.data.U['sessionkey'];

            Ctxt.Server.Sessions.Safe.Lock;
            try
              // Search session for User
              if (reOneSessionPerUser in Ctxt.Call^.RestAccessRights^.AllowRemoteExecute) and
                 (Ctxt.Server.Sessions<>nil) then
                for i := 0 to Pred(Ctxt.Server.Sessions.Count) do
                  if TAuthSession(Ctxt.Server.Sessions[i]).User.ID = User.ID then begin
                    Result := TAuthSession(Ctxt.Server.Sessions[i]);
                    Ctxt.Session := Result.IDCardinal;
                    break;
                  end;

              // Search session by privatesalt
              if result = nil then
                for i := 0 to Pred(Ctxt.Server.Sessions.Count) do
                  if SameTextU(vSessionPrivateSalt, TAuthSession(Ctxt.Server.Sessions[i]).ID + '+' + TAuthSession(Ctxt.Server.Sessions[i]).PrivateKey) then begin
                    Result := TAuthSession(Ctxt.Server.Sessions[i]);
                    Ctxt.Session := Result.IDCardinal;
                    break;
                  end;

            finally
              Ctxt.Server.Sessions.Safe.unLock;
            end;
          end;
        end;
      finally
        User.free;
      end;
    end;
end;

procedure TSQLRestServerAuthenticationJWT.SessionCreate(
  Ctxt: TSQLRestServerURIContext; var User: TSQLAuthUser);
var i : Integer;
    Token : RawUTF8;
    jWtClass : TJWTSynSignerAbstractClass;
    vPass, vUser, Signat, vSessionKey : RawUTF8;
    vTmp : TDocVariantData;
begin
  vUser := User.LogonName;
  vPass := User.PasswordHashHexa;

  inherited SessionCreate(Ctxt, User);

  if Ctxt.Call^.OutStatus = HTTP_SUCCESS then begin
    vTmp.InitJSON(Ctxt.Call^.OutBody);
    if vTmp.Kind <> dvUndefined then
      if fServer.JWTForUnauthenticatedRequest <> nil then begin
        jwtClass := JWT_CLASS[getAlgo(fServer.JWTForUnauthenticatedRequest.Algorithm)];
        vSessionKey := vTmp.U['result'];
        Token := (fServer.JWTForUnauthenticatedRequest as jwtClass).Compute([ 'sessionkey', vSessionKey],
                                                                           vUser,
                                                                           'jwt.access',
                                                                           '',0,JWTDefaultTimeout, @Signat);

        Ctxt.Call^.OutBody := _Obj(['result', vTmp.U['result'], 'access_token', Token]);
      end;
  end;
end;

{ TSQLHttpClientJWT }

function TSQLHttpClientJWT.InternalRequest(const url, method: RawUTF8;
  var Header, Data, DataType: RawUTF8): Int64Rec;
var vBasic : RawUTF8;
    h : Integer;
begin
  if fjwt <> '' then begin // Change Header if jwt exist
    vBasic := HeaderOnce(Header, 'AUTHORIZATION: BASIC ');
    if vBasic <> '' then begin
      h := PosEx(vBasic, Header);
      if h = 22 then
        header := copy(Header, h + Length(vBasic), Length(header))
      else header := copy(Header, 1, h - 21) + copy(Header, h + Length(vBasic), Length(header));
      header := Trim(header);
    end;
    Header := trim(HEADER_BEARER_UPPER + fJWT + #13#10 + Header);
  end;
  result := inherited InternalRequest(url, method, Header, Data, DataType);
end;

procedure TSQLHttpClientJWT.InternalSetClass;
begin
  fRequestClass := TWinHTTP;
  inherited;
end;

function TSQLHttpClientJWT.SetUser(const aUserName, aPassword: RawUTF8;
  aHashedPassword: Boolean): boolean;
const HASH: array[boolean] of TSQLRestServerAuthenticationClientSetUserPassword =
  (passClear, passHashed);
begin
  if self=nil then begin
    result := false;
    exit;
  end;
  result := TSQLRestServerAuthenticationJWT.
    ClientSetUser(self,aUserName,aPassword,HASH[aHashedPassword]);
end;

end.

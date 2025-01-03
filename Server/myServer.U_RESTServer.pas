unit myServer.U_RESTServer;

interface
uses sysutils,
     Vcl.Dialogs,
     Vcl.Forms,
     Syncommons,
     Mormot,
     MormotSqlite3,
     SynSQLite3,
     synCrypto,
     SynCrtSock,
     SynBidirSock,
     MormotHttpServer,
     mORMotWrappers,
     RestServer.U_JWT,
     RestServer.U_Data,
     RestServer.U_Const;
type
  TRegisterServicesCallBack = reference to Procedure(const aServer : TSQLRestServerDB);
  TRegisterSQLModels = reference to Function(const aRoot : RawUTF8) : TSQLModel;

  TServerDTB = class(TSQLRestServerDB)
  published
    Function IsValidToken(aParams: TSQLRestServerURIContext): Integer;
    Function RefreshToken(aParams: TSQLRestServerURIContext): Integer;
  end;

type
  lProtocol = (HTTP_Socket                       = 0,
               HTTPsys                           = 1,
               HTTPsys_SSL                       = 2,
               HTTPsys_AES                       = 3,
               HTTP_WebSocket                    = 4,
               WebSocketBidir_JSON               = 5,
               WebSocketBidir_Binary             = 6,
               WebSocketBidir_BinaryAES          = 7,
               NamedPipe                         = 8);

  lAuthenticationMode = (Default                 = 1,  // AES256
                         None                    = 2,
                         HttpBasic               = 3,
                         SSPI                    = 4,
                         JWT_HS256               = 5,
                         JWT_HS384               = 6,
                         JWT_HS512               = 7,
                         JWT_S3224               = 8,
                         JWT_S3256               = 9,
                         JWT_S3384               = 10,
                         JWT_S3512               = 11,
                         JWT_S3S128              = 12,
                         JWT_S3S256              = 13
                         );

const
  AUTH_ISJWT : Array[lAuthenticationMode] of Boolean = (False, False, False, False,
                                                        True, True, True, True,
                                                        True, True, True, True,
                                                        True);
  AUTH_ALGO : Array[lAuthenticationMode] of TSignAlgo = (saSha1, saSha1, saSha1, saSha1,
                                                        saSha256, saSha384, saSha512,
                                                        saSha3224, saSha3256, saSha3384, saSha3512,
                                                        saSha3S128, saSha3S128);

type

  TRestServerSettings = class
  private
    FRegisterServices   : TRegisterServicesCallBack;
    FSQLModels          : TRegisterSQLModels;
    fAuthSessionClass   : TAuthSessionClass;
    fAuthenticationJWTClass : TSQLRestServerAuthenticationJWTClass;
  public
    Protocol            : lProtocol;
    Port                : string;
    WEBSERVER_URIROOT   : SockString;
    NAMED_PIPE_NAME     : TFileName;
    AuthenticationMode  : lAuthenticationMode;

    constructor Create;
    destructor Destroy; override;

    procedure DefineRegisterSQLModels(const aFunc : TRegisterSQLModels);
    function  SQLModels : TRegisterSQLModels;

    procedure DefineRegisterServices(const aFunc : TRegisterServicesCallBack);
    function  RegisterServices : TRegisterServicesCallBack;

    property AuthSessionClass : TAuthSessionClass read fAuthSessionClass write fAuthSessionClass;
    property AuthenticationJWTClass : TSQLRestServerAuthenticationJWTClass read fAuthenticationJWTClass write fAuthenticationJWTClass;
  end;

  // Serveur REST principal
  TRestServer = class
  private
    fModel          : TSQLModel;
    fRestServer     : TServerDTB;
    fHTTPServer     : TSQLHttpServer;
    fServerSettings : TRestServerSettings;
    fInitialized    : boolean;

    procedure _RegisterInternalServices;
  public
    constructor Create;
    destructor Destroy; override;

    function Initialize(SrvSettings : TRestServerSettings): boolean;
    function DeInitialize: boolean;

    Function Settings     : TRestServerSettings;
    property Initialized  : boolean         read fInitialized;
    property RestServer   : TServerDTB     read fRestServer;
  end;

var MainServer  : TRestServer;

implementation

{ TRestServerSettings }

constructor TRestServerSettings.Create;
begin
  inherited;
  Port                := '80';
  AuthenticationMode  := lAuthenticationMode.Default;
  Protocol            := HTTPsys_AES;
  FRegisterServices   := nil;
  FSQLModels          := nil;
  fAuthSessionClass   := TAuthSession;
  fAuthenticationJWTClass := TSQLRestServerAuthenticationJWT;
end;

procedure TRestServerSettings.DefineRegisterServices(
  const aFunc: TRegisterServicesCallBack);
begin
  FRegisterServices := nil;
  FRegisterServices := aFunc;
end;

procedure TRestServerSettings.DefineRegisterSQLModels(
  const aFunc: TRegisterSQLModels);
begin
  FSQLModels := nil;
  FSQLModels := AFunc;
end;

destructor TRestServerSettings.Destroy;
begin
  FRegisterServices := nil;
  FSQLModels        := nil;
  inherited;
end;

function TRestServerSettings.RegisterServices: TRegisterServicesCallBack;
begin
  Result := FRegisterServices;
end;

function TRestServerSettings.SQLModels: TRegisterSQLModels;
begin
  Result := FSQLModels;
end;

{ TRestServer }

constructor TRestServer.Create;
begin
  inherited;
  fInitialized := False;
end;

function TRestServer.DeInitialize: boolean;
begin
  Result := True;
  try
    if Assigned(fHTTPServer) and (fHTTPServer.HttpServer.ClassType = THttpApiServer) then
      THttpApiServer(fHTTPServer.HttpServer).RemoveUrl(fServerSettings.WEBSERVER_URIROOT, fHTTPServer.Port, fServerSettings.Protocol = HTTPsys_SSL, '+');
    if Assigned(fHTTPServer) then
      FreeAndNil(fHTTPServer);
    if Assigned(fRestServer) then
      FreeAndNil(fRestServer);
    if Assigned(fModel) then
      FreeAndNil(fModel);

    fInitialized := false;
  except
    on E: Exception do
      begin
        ShowMessage(E.ToString);
        Result := false;
      end;
  end;
end;

destructor TRestServer.Destroy;
begin
  DeInitialize();
  if fServerSettings <> nil then
    fServerSettings.Free;
  inherited;
end;

function TRestServer.Initialize(SrvSettings: TRestServerSettings): boolean;
var
  vRight : TSQLAuthGroup;
  vUser  : TAuthUser;
  vPath  : TFileName;
  vPathTemplate  : TFileName;
  vGUID : TGUID;
begin
  Result        := False;
  fInitialized  := False;

  if not assigned(SrvSettings) then Exit;
  if not assigned(SrvSettings.FRegisterServices) then begin
    Raise Exception.Create('SrvSettings.FRegisterServices = NIL !');
    Exit;
  end;

  if DeInitialize() then try

    // RestServer initialization (database)
    vPath           := ChangeFileExt(Application.ExeName,'.edb');
    vPathTemplate   := IncludeTrailingPathDelimiter(ExtractFilePath(Application.ExeName)) + 'template';
    if not DirectoryExists(vPathTemplate) then ForceDirectories(vPathTemplate);

    if Assigned(SrvSettings.FSQLModels) then fModel := SrvSettings.FSQLModels(SrvSettings.WEBSERVER_URIROOT)
    else fModel := DTBModelBase(SrvSettings.WEBSERVER_URIROOT);
    fRestServer := TServerDTB.Create(fModel, vPath, true);

    if SrvSettings.AuthSessionClass = nil then Raise Exception.Create('AuthSessionClass Not Defined');
    fRestServer.fSessionClass := SrvSettings.AuthSessionClass; // Inject Custom TAuthSession

    fRestServer.DB.Synchronous := smOff;
    fRestServer.DB.LockingMode := lmNormal;
    fRestServer.DB.UseCache    := True;
    fRestServer.CreateMissingTables;

    _RegisterInternalServices;
    SrvSettings.FRegisterServices(fRestServer);

    if assigned(fServerSettings) then fServerSettings.Free;
    fServerSettings := nil;
    fServerSettings := SrvSettings;

    if AUTH_ISJWT[fServerSettings.AuthenticationMode] then begin
      fRestServer.ServiceMethodByPassAuthentication('IsValidToken');
      fRestServer.ServiceMethodByPassAuthentication('RefreshToken');
    end;

    AddToServerWrapperMethod(fRestServer, [vPathTemplate]);

    fRestServer.AuthenticationUnregisterAll;
    // Authentification initialization
    case fServerSettings.AuthenticationMode of
      Default           : fRestServer.AuthenticationRegister(TSQLRestServerAuthenticationDefault);
      None              : fRestServer.AuthenticationRegister(TSQLRestServerAuthenticationNone);
      HttpBasic         : fRestServer.AuthenticationRegister(TSQLRestServerAuthenticationHttpBasic);
      JWT_HS256, JWT_HS384, JWT_HS512, JWT_S3224,
      JWT_S3256, JWT_S3384, JWT_S3512, JWT_S3S128, JWT_S3S256 :
      begin
        fRestServer.AuthenticationRegister(fServerSettings.AuthenticationJWTClass);
        fRestServer.ServicesRouting := TSQLRestRoutingREST_JWT;
        CreateGUID(vGUID);
        fRestServer.JWTForUnauthenticatedRequest := JWT_CLASS[AUTH_ALGO[fServerSettings.AuthenticationMode]].Create(SHA256(GUIDToRawUTF8(vGUID)), 0, [jrcIssuer, jrcSubject], [], JWTDefaultTimeout);
      end;
      {$IFDEF SPPIAUTH}
      SSPI              : fRestServer.AuthenticationRegister(TSQLRestServerAuthenticationSSPI);
      {$ENDIF}
      else begin
        DeInitialize();
        raise Exception.Create('Selected authentication not available in this version.');
      end;
    end;

    // protocol initialization (HttpServer)
    case fServerSettings.Protocol of
      HTTP_Socket:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useHttpSocket);
          THttpServer(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
        end;
      HTTPsys:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useHttpApiRegisteringURI);
          THttpServer(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
        end;
      HTTPsys_SSL:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useHttpApiRegisteringURI, 32, TSQLHttpServerSecurity.secSSL);
          THttpServer(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
        end;
      HTTPsys_AES:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useHttpApiRegisteringURI, 32, TSQLHttpServerSecurity.secSynShaAes);
          THttpServer(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
        end;
      HTTP_WebSocket:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useBidirSocket);
          TWebSocketServerRest(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
        end;
      WebSocketBidir_JSON:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useBidirSocket);
          TWebSocketServerRest(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
          fHTTPServer.WebSocketsEnable(fRestServer, '', True);
        end;
      WebSocketBidir_Binary:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useBidirSocket);
          TWebSocketServerRest(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
          fHTTPServer.WebSocketsEnable(fRestServer, '', false);
        end;
      WebSocketBidir_BinaryAES:
        begin
          fHTTPServer := TSQLHttpServer.Create(AnsiString(fServerSettings.Port), [fRestServer], '+', useBidirSocket);
          TWebSocketServerRest(fHTTPServer.HttpServer).ServerKeepAliveTimeOut := CONNECTION_TIMEOUT;
          fHTTPServer.WebSocketsEnable(fRestServer, '2141D32ADAD54D9A9DB56000CC9A4A70', false); // #TODO1 :Review the key
        end;
      NamedPipe:
        begin
          if not fRestServer.ExportServerNamedPipe(SrvSettings.NAMED_PIPE_NAME) then
            Exception.Create('Unable to register server on Name Pipe layer.');
        end;
    else
      begin
        DeInitialize();
        raise Exception.Create('Protocol not available on this version.');
      end;
    end;
     fHTTPServer.AccessControlAllowOrigin := '*';
    Result := True;
  except
    on E: Exception do
      begin
        ShowMessage(E.ToString);
        DeInitialize();
      end;
  end;
  fInitialized := Result;
end;

function TRestServer.Settings: TRestServerSettings;
begin
  Result := fServerSettings;
end;

procedure TRestServer._RegisterInternalServices;
begin

end;

{ TServerDTB }

function TServerDTB.IsValidToken(aParams: TSQLRestServerURIContext): Integer;
var JWTContent : TJWTContent;
    vResult : TDocVariantData;
    nowunix : TUnixTime;
    unix : Cardinal;
    _result : Boolean;
    vExpired : TDateTime;
    jWtClass : TJWTSynSignerAbstractClass;
    TokenSesID : Cardinal;
    SessionExist : Boolean;
    i : Integer;
begin
  result := HTTP_UNAVAILABLE;
  try
    if not Assigned(MainServer.RestServer) then begin
      aParams.Returns('Server not initialized', HTTP_NOTFOUND);
      Exit;
    end;

    if not Assigned(MainServer.RestServer.JWTForUnauthenticatedRequest) then begin
      aParams.Returns('TSQLRestServerAuthenticationJWT non initialized', HTTP_NOTFOUND);
      Exit;
    end;

    jwtClass := JWT_CLASS[getAlgo(MainServer.RestServer.JWTForUnauthenticatedRequest.Algorithm)];
    _Result := CurrentServiceContext.Request.AuthenticationCheck((MainServer.RestServer.JWTForUnauthenticatedRequest as jwtClass));
    if not _result then
      aParams.Returns(synCrypto.ToText(CurrentServiceContext.Request.JWTContent.Result)^, HTTP_FORBIDDEN)
    else begin
      SessionExist := False;
      if MainServer.RestServer.Sessions <> nil then begin
        TokenSesID := GetCardinal(Pointer(CurrentServiceContext.Request.JWTContent.data.U['sessionkey']));
        if TokenSesID > 0 then
          for i := 0 to pred(MainServer.RestServer.Sessions.Count) do begin
            if (TAuthSession(MainServer.RestServer.Sessions[i]).IDCardinal = TokenSesID) then begin
              SessionExist := True;
              Break;
            end;
          end;
      end;

      if SessionExist then begin
        vResult.InitFast;
        if jrcExpirationTime in CurrentServiceContext.Request.JWTContent.claims then
           if ToCardinal(CurrentServiceContext.Request.JWTContent.reg[jrcExpirationTime],unix) then begin
             nowunix := UnixTimeUTC;
             vExpired := UnixTimeToDateTime(unix - nowunix);
             vResult.AddValue('ExpiredIn', FormatDateTime('hh:nn:ss', vExpired));
           end
           else vResult.AddValue('ExpiredIn','');
        aParams.Returns(Variant(vResult), HTTP_SUCCESS);
      end
      else aParams.Returns('Session unknown', HTTP_FORBIDDEN);
    end;
  Except
    on e : exception do
     aParams.Returns(StringToUTF8(e.Message), HTTP_NOTFOUND);
  end;
end;

function TServerDTB.RefreshToken(aParams: TSQLRestServerURIContext): Integer;
var Token, vUserName, vPassword, signat : RawUTF8;
    vResult : TDocVariantData;
    jWtClass : TJWTSynSignerAbstractClass;
    User : TSQLAuthUser;
    i : Integer;
    TokenSesID : Cardinal;
    SessionExist : Boolean;
    NewSession : TAuthSession;
    nowunix : TUnixTime;
    unix : Cardinal;
begin
  result := HTTP_UNAVAILABLE;
  try
    if not Assigned(MainServer.RestServer) then begin
      aParams.Returns('Server not initialized', HTTP_NOTFOUND);
      Exit;
    end;

    if not Assigned(MainServer.RestServer.JWTForUnauthenticatedRequest) then begin
      aParams.Returns('TSQLRestServerAuthenticationJWT not initialized', HTTP_NOTFOUND);
      Exit;
    end;

    if UrlDecodeNeedParameters(aParams.Parameters,'USERNAME,PASSWORD') then begin
      while aParams.Parameters<>nil do begin
        UrlDecodeValue(aParams.Parameters,'USERNAME=',    vUserName,   @aParams.Parameters);
        UrlDecodeValue(aParams.Parameters,'PASSWORD=',    vPassword,   @aParams.Parameters);
      end;

      vResult.InitFast;

      jwtClass := JWT_CLASS[getAlgo(MainServer.RestServer.JWTForUnauthenticatedRequest.Algorithm)];
      Token := CurrentServiceContext.Request.AuthenticationBearerToken;
      CurrentServiceContext.Request.AuthenticationCheck((MainServer.RestServer.JWTForUnauthenticatedRequest as jwtClass));

      if CurrentServiceContext.Request.JWTContent.result in [jwtValid, jwtExpired] then begin
        User := MainServer.RestServer.fSQLAuthUserClass.Create(MainServer.RestServer,'LogonName=?',[vUserName]);
        if Assigned(User) then try
          if User.ID <= 0 then aParams.Returns('Unknown user', HTTP_FORBIDDEN)
          else if SameTextU(User.PasswordHashHexa, SHA256('salt' + vPassword)) or
                  SameTextU(User.PasswordHashHexa, vPassword) then begin

            SessionExist := False;
            if MainServer.RestServer.Sessions <> nil then begin
              TokenSesID := GetCardinal(Pointer(CurrentServiceContext.Request.JWTContent.data.U['sessionkey']));
              if TokenSesID > 0 then
                for i := 0 to pred(MainServer.RestServer.Sessions.Count) do begin
                  if (TAuthSession(MainServer.RestServer.Sessions[i]).UserID = User.ID) and
                     (TAuthSession(MainServer.RestServer.Sessions[i]).IDCardinal = TokenSesID) then begin
                    SessionExist := True;
                    Break;
                  end;
                end;
            end;

            if SessionExist and (CurrentServiceContext.Request.JWTContent.result = jwtValid) then begin
              // Nothing to do ! just return current Token
              vResult.AddValue('jwt', Token);
              aParams.Returns(Variant(vResult), HTTP_SUCCESS);
            end
            else begin
              if (CurrentServiceContext.Request.JWTContent.result = jwtExpired) then
                if jrcExpirationTime in CurrentServiceContext.Request.JWTContent.claims then
                  if ToCardinal(CurrentServiceContext.Request.JWTContent.reg[jrcExpirationTime],unix) then begin
                    nowunix := UnixTimeUTC;
                    if UnixTimeToDateTime(nowunix - unix) > JWTDefaultRefreshTimeOut then begin
                      aParams.Returns('jwt : expiration time to long', HTTP_FORBIDDEN);
                      Exit;
                    end;
                  end;

              jwtClass := JWT_CLASS[getAlgo(MainServer.RestServer.JWTForUnauthenticatedRequest.Algorithm)];
              if SessionExist then
                Token := (MainServer.RestServer.JWTForUnauthenticatedRequest as jwtClass)
                             .Compute(['sessionkey', Variant(CurrentServiceContext.Request.JWTContent.data.U['sessionkey'])],
                                       vUserName,
                                       'jwt.access',
                                       '',0,JWTDefaultTimeout, @Signat)
              else begin
                MainServer.RestServer.SessionCreate(User, CurrentServiceContext.Request, NewSession);
                if NewSession <> nil then
                  Token := (MainServer.RestServer.JWTForUnauthenticatedRequest as jwtClass)
                               .Compute(['sessionkey', NewSession.ID + '+' + NewSession.PrivateKey],
                                         vUserName,
                                         'jwt.access',
                                         '',0,JWTDefaultTimeout, @Signat)
                else begin
                  aParams.Returns('Invalid sessionCreate result', HTTP_FORBIDDEN);
                  Exit;
                end;
              end;
              vResult.AddValue('refresh_token', Token);
              aParams.Returns(Variant(vResult), HTTP_SUCCESS);
            end;
          end
          else aParams.Returns('Invalid password', HTTP_FORBIDDEN);
        finally
          User.Free;
        end
        else aParams.Returns('unknown user', HTTP_FORBIDDEN);
      end
      else aParams.Returns(synCrypto.ToText(CurrentServiceContext.Request.JWTContent.result)^, HTTP_FORBIDDEN)
    end
    else begin
      aParams.Returns('Incorrect settings', HTTP_NOTFOUND);
      Exit;
    end;

  Except
    on e : exception do
     aParams.Returns(StringToUTF8(e.Message), HTTP_NOTFOUND);
  end;
end;

initialization
  MainServer := TRestServer.Create();

finalization
  if Assigned(MainServer) then
    FreeAndNil(MainServer);


end.

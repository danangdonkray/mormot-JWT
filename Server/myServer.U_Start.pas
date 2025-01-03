unit myServer.U_Start;

interface
uses
  SynCommons,
  mORMot,
  mORMotSQLite3,
  myServer.U_RESTServer,
  RestServer.U_JWT,
  RestServer.U_DTB;

procedure InitializeServer();
procedure FinalizeServer();

implementation
uses RestServer.I_RestInterface, RestServer.U_myMethods;

procedure InitializeServer();
var
  LInitialized: Boolean;
  LParams: TRestServerSettings;
  TmpData : TSampleData;
begin
  LInitialized := MainServer.Initialized;
  if LInitialized then
    MainServer.DeInitialize();

  LParams := TRestServerSettings.Create();
  LParams.Port := '888';
  LParams.Protocol := HTTPsys_AES;
  LParams.AuthenticationMode := lAuthenticationMode.JWT_HS256;
  LParams.AuthenticationJWTClass := TSQLRestServerAuthenticationJWT;

  LParams.WEBSERVER_URIROOT := 'api/service/';
  LParams.AuthSessionClass := TAuthSession;
  LParams.DefineRegisterServices(
    procedure(const AServer: TSQLRestServerDB)
    begin
      if not Assigned(AServer) then
        Exit;
      AServer.ServiceDefine(TmyMethods, [IInterface], sicPerSession, SERVICE_CONTRACT_NONE_EXPECTED);
    end);
  LParams.DefineRegisterSQLModels(
    function(const ARoot: RawUTF8): TSQLModel
    begin
      Result := DTBModel(ARoot);
    end);

  MainServer.Initialize(LParams);

  // Make sample data
  TmpData := TSampleData.Create;
  try
    TmpData.FillPrepare(MainServer.RestServer, 'LIMIT 1', '');
    if not TmpData.FillOne then begin
      TmpData.FirstName := 'danang';
      TmpData.LastName  := 'Test';
      MainServer.RestServer.Add(TmpData, true);

      TmpData.FirstName := 'dion';
      TmpData.LastName  := 'Test';
      MainServer.RestServer.Add(TmpData, true);

      TmpData.FirstName := 'deni';
      TmpData.LastName  := 'Test';
      MainServer.RestServer.Add(TmpData, true);
    end;
  finally
    TmpData.Free;
  end;
end;

procedure FinalizeServer();
begin
  MainServer.DeInitialize();
end;

end.

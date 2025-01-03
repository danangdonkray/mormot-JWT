program myServer;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SynCommons,
  mORMot,
  Windows,
  SynLog,
  System.SysUtils,
  SynSQLite3Static,
  myServer.U_RESTServer in 'myServer.U_RESTServer.pas',
  RestServer.U_JWT in '..\Common\RestServer.U_JWT.pas',
  RestServer.U_Data in '..\Common\RestServer.U_Data.pas',
  RestServer.U_Const in '..\Common\RestServer.U_Const.pas',
  myServer.U_Start in 'myServer.U_Start.pas',
  RestServer.U_DTB in '..\Common\RestServer.U_DTB.pas',
  RestServer.I_RestInterface in '..\Common\RestServer.I_RestInterface.pas',
  RestServer.U_myMethods in '..\Common\RestServer.U_myMethods.pas';

const
  ENABLE_QUICK_EDIT_MODE = $40;
  ENABLE_EXTENDED_FLAGS = $80;

  var
    h: NativeUInt;
    OldMode: Cardinal;

begin
  try
     h := GetStdHandle(STD_INPUT_HANDLE);
    if not (
      GetConsoleMode(h, OldMode) and
      SetConsoleMode(h, OldMode and not ENABLE_QUICK_EDIT_MODE or ENABLE_EXTENDED_FLAGS)
    )
    then
      RaiseLastOSError;

    // Do stuff

    with TSQLLog.Family do
    begin
      Level := LOG_VERBOSE;
      EchoToConsole := LOG_STACKTRACE;
      NoFile := True;
    end;

    InitializeServer();
    try
      Writeln('Press [Enter] to stop the server.'#10);
      Readln;

    finally
      FinalizeServer();
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

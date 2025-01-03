unit RestServer.U_Sample;

interface
uses
  SynCommons,
  mOrmot,
  RestServer.I_Sample,
  myServer.U_RESTServer,
  RestServer.U_DTB;

type
  TSample = class(TInterfacedObject, ISample)
  private
    FLocker: TSynLocker;
  public
    procedure FreeInstance(); override;
    class function NewInstance(): TObject; override;
  published
    function FullList : TServiceCustomAnswer;
  end;

implementation

{ TSample }

procedure TSample.FreeInstance;
begin
  FLocker.Done();
  inherited FreeInstance();
end;

function TSample.FullList: TServiceCustomAnswer;
var L : TSQLTableJSON;
    tmp : variant;
begin
  FLocker.Lock();
  try
    Result.Header := JSON_CONTENT_TYPE_HEADER;
    L := MainServer.RestServer.ExecuteList([TSampleData], 'SELECT * FROM SAMPLEDATA LIMIT 100');
    if Assigned(L) then begin
      tmp := _Arr([]);
      L.ToDocVariant(tmp, true);
      Result.Content := tmp;
      L.Free;
    end;
    Result.Status := HTTP_SUCCESS;
  finally
    FLocker.UnLock();
  end;
end;

class function TSample.NewInstance: TObject;
begin
  Result := inherited NewInstance();
  TSample(Result).FLocker.Init();
end;

end.

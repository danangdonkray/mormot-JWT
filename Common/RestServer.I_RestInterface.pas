unit RestServer.I_RestInterface;

interface
uses
  SynCommons,
  mOrmot;

type
  IInterface = interface(IInvokable)
  ['{7CB8BE69-5D57-4D72-AE8E-EB69F7674CC6}']
    function HelloWorld():string;
    function SUM(a,b:Integer):string;
    function FullList : TServiceCustomAnswer;

    //request body json
    function tesjson(const data : RawJSON) : string;
  end;

implementation

initialization
  TInterfaceFactory.RegisterInterfaces([TypeInfo(IInterface)]);

end.

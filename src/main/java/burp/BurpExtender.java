package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;


/**
 * @author bugzy
 */
public class BurpExtender implements IBurpExtender, IHttpListener, ITab{

    public String ExtensionName =  "Strict Replay (SRePlay)";
    public String TabName   =  "SRePlay";
    public String myHeader  = "SRePlay: Bypass";

    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    
    
    public Boolean isDebug      = false;
    public Boolean _repeater    = false;
    public Boolean _intruder    = false;
    public Boolean _scanner     = false;
       
    
    public SRePlay _SRePlay;
    public String _host;
    public String _parameter;
    public String _value;
    
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks.setExtensionName(this.ExtensionName);
        this._SRePlay = new SRePlay(this);

        this.callbacks.addSuiteTab(this);
        this.stdout.println("SRePlay - Installed !!!");
    }

    private void print_output(String _src, String str){
        if(! isDebug){ return; }
        this.stdout.println(_src + " :: " + str);
    }
    
    private void print_error(String _src, String str){
        if(! isDebug){ return; }
        this.stderr.println(_src + " :: " + str);
    }
    
       
    public void start_SRePlay(){
        this.callbacks.registerHttpListener(this);
    }

    
    public void stop_SRePlay(){
        this.callbacks.removeHttpListener(this);
    }


    public String get_host(String _url){
        try{
            URL abc = new URL(_url);
            return abc.getHost().toString();
        }catch (Exception ex){
            print_error("get_host", _url);
            return _url;
        }
    }


    @Override
    public String getTabCaption() {
        return this.TabName;
    }


    @Override
    public Component getUiComponent() {
        return this._SRePlay;
    }
    
    
    private String update_req_json(byte[] _req, String _param, String _value){
        byte[] _tmp_req = _req;
        
        IRequestInfo reqInfo = helpers.analyzeRequest(_tmp_req);
        String tmpreq = new String(_tmp_req);
        String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
        
        int _fi = messageBody.indexOf(_param);
        if(_fi < 0) { return messageBody; }
        
        _fi = _fi + _param.length() + 3;
        int _si = messageBody.indexOf("\",", _fi);
        
        
        messageBody = messageBody.substring(0, _fi) + _value + messageBody.substring(_si, messageBody.length());
        return messageBody;
    }
    
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(messageIsRequest){
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();
            
            if(IBurpExtenderCallbacks.TOOL_REPEATER != toolFlag && IBurpExtenderCallbacks.TOOL_INTRUDER != toolFlag && IBurpExtenderCallbacks.TOOL_SCANNER != toolFlag){ return; }
             
            if(this._host.contains(get_host(URL))){
                byte[] _request = messageInfo.getRequest();
                
                if(reqInfo.getContentType() == 4){
                    String messageBody = update_req_json(_request, _parameter, _value);
                    headers.add(this.myHeader);
                    _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
                }
                else {
                    IParameter _p = this.helpers.getRequestParameter(_request, _parameter);
                    if (_p == null || _p.getName().toString().length() == 0){ return; }
                    IParameter _newP = this.helpers.buildParameter(_parameter, _value, _p.getType());
                    _request = this.helpers.removeParameter(_request, _p);
                    _request = this.helpers.addParameter(_request, _newP);
                    headers.add(this.myHeader);
                    
                    IRequestInfo reqInfo2 = helpers.analyzeRequest(_request);
                    String tmpreq = new String(_request);
                    String messageBody = new String(tmpreq.substring(reqInfo2.getBodyOffset())).trim();
                    _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
                }

                messageInfo.setRequest(_request);
            }
            
        }
        else{
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();
            
            if(IBurpExtenderCallbacks.TOOL_REPEATER != toolFlag && IBurpExtenderCallbacks.TOOL_INTRUDER != toolFlag && IBurpExtenderCallbacks.TOOL_SCANNER != toolFlag){ return; }

            if(!headers.contains(this.myHeader)){
                return;
            }

            if(this._host.contains(get_host(URL))){
                byte[] _response = messageInfo.getResponse();
                IParameter _p = this.helpers.getRequestParameter(_response, _parameter);
                if (_p == null || _p.getName().toString().length() == 0){ return; }
                this._value = _p.getValue().toString();
            }
        }
    }
}
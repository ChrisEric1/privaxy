use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;
use tokio::fs;
use url::Url;

use serde_with::{serde_as, DisplayFromStr};
pub(crate) const FILTERS_DIRECTORY_NAME: &str = "filters";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

impl ToString for FilterGroup {
    fn to_string(&self) -> String {
        match self {
            FilterGroup::Default => "default",
            FilterGroup::Regional => "regional",
            FilterGroup::Ads => "ads",
            FilterGroup::Privacy => "privacy",
            FilterGroup::Malware => "malware",
            FilterGroup::Social => "social",
        }
        .to_string()
    }
}

#[serde_as]
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DefaultFilter {
    enabled_by_default: bool,
    file_name: String,
    group: String,
    title: String,
    #[serde_as(as = "DisplayFromStr")]
    url: Url,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Filter {
    /// If the filter is enabled
    pub enabled: bool,
    /// Title of the filter
    pub title: String,
    /// Group of the filter
    pub group: FilterGroup,
    /// Local file name of the filter
    pub file_name: String,
    #[serde_as(as = "DisplayFromStr")]
    /// Remote URL of the filter
    pub url: Url,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DefaultFilters(Vec<DefaultFilter>);

impl DefaultFilters {
    pub fn new() -> Self {
        let mut filters = Vec::new();
        filters.extend(Self::get_cecl_filters());
        DefaultFilters(filters)
    }

    pub fn list(&self) -> Vec<DefaultFilter> {
        self.0.clone()
    }

    fn parse_filter(
        url: &'static str,
        title: &'static str,
        group: FilterGroup,
        enabled_by_default: bool,
    ) -> Option<DefaultFilter> {
        match Url::parse(url) {
            Ok(parsed_url) => {
                let file_name = calc_filter_filename(url);
                Some(DefaultFilter {
                    enabled_by_default,
                    file_name,
                    group: group.to_string(),
                    title: title.to_string(),
                    url: parsed_url,
                })
            }
            Err(e) => {
                log::warn!("Failed to parse URL {}: {}", url, e);
                None
            }
        }
    }

    fn get_cecl_filters() -> Vec<DefaultFilter> {
        vec![
            ("http://adblock.ee/list.txt", "http://adblock.ee/list.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/NorwegianList.txt", "http://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/NorwegianList.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/SerboCroatianList.txt", "http://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/SerboCroatianList.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/EasyList-Lithuania/easylist_lithuania@master/easylistlithuania.txt", "http://cdn.jsdelivr.net/gh/EasyList-Lithuania/easylist_lithuania@master/easylistlithuania.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/List-KR/List-KR@latest/filter-uBlockOrigin.txt", "http://cdn.jsdelivr.net/gh/List-KR/List-KR@latest/filter-uBlockOrigin.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/MasterKia/PersianBlocker@main/PersianBlocker.txt", "http://cdn.jsdelivr.net/gh/MasterKia/PersianBlocker@main/PersianBlocker.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/dimisa-RUAdList/RUAdListCDN@main/lists/ruadlist.ubo.min.txt", "http://cdn.jsdelivr.net/gh/dimisa-RUAdList/RUAdListCDN@main/lists/ruadlist.ubo.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/easylist/ruadlist@master/cntblock.txt", "http://cdn.jsdelivr.net/gh/easylist/ruadlist@master/cntblock.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/hufilter/hufilter@gh-pages/hufilter-ublock.txt", "http://cdn.jsdelivr.net/gh/hufilter/hufilter@gh-pages/hufilter-ublock.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/lassekongo83/Frellwits-filter-lists@swefilter/swefilter.min.txt", "http://cdn.jsdelivr.net/gh/lassekongo83/Frellwits-filter-lists@swefilter/swefilter.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/annoyances-cookies.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/annoyances-cookies.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/annoyances.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/annoyances.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badlists.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badlists.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badware.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badware.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/filters.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/filters.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/lan-block.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/lan-block.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/privacy.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/privacy.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/quick-fixes.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/quick-fixes.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/unbreak.min.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/unbreak.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-annoyances.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-annoyances.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-chat.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-chat.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-cookies.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-cookies.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-newsletters.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-newsletters.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-notifications.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-notifications.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-social.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist-social.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easylist.txt's filters", FilterGroup::Default, true),
            ("http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easyprivacy.txt", "http://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/thirdparties/easyprivacy.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt", "http://cdn.statically.io/gh/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/MasterKia/PersianBlocker/main/PersianBlocker.txt", "http://cdn.statically.io/gh/MasterKia/PersianBlocker/main/PersianBlocker.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/dimisa-RUAdList/RUAdListCDN/main/lists/ruadlist.ubo.min.txt", "http://cdn.statically.io/gh/dimisa-RUAdList/RUAdListCDN/main/lists/ruadlist.ubo.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/easylist/ruadlist/master/cntblock.txt", "http://cdn.statically.io/gh/easylist/ruadlist/master/cntblock.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/annoyances-cookies.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/annoyances-cookies.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/annoyances.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/annoyances.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/badlists.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/badlists.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/badware.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/badware.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/filters.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/filters.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/lan-block.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/lan-block.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/privacy.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/privacy.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/quick-fixes.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/quick-fixes.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/unbreak.min.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/filters/unbreak.min.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-annoyances.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-annoyances.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-chat.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-chat.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-cookies.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-cookies.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-newsletters.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-newsletters.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-notifications.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-notifications.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-social.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist-social.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easylist.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easyprivacy.txt", "http://cdn.statically.io/gh/uBlockOrigin/uAssetsCDN/main/thirdparties/easyprivacy.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gl/DandelionSprout/adfilt/master/NorwegianList.txt", "http://cdn.statically.io/gl/DandelionSprout/adfilt/master/NorwegianList.txt's filters", FilterGroup::Default, true),
            ("http://cdn.statically.io/gl/DandelionSprout/adfilt/master/SerboCroatianList.txt", "http://cdn.statically.io/gl/DandelionSprout/adfilt/master/SerboCroatianList.txt's filters", FilterGroup::Default, true),
            ("http://curbengh.github.io/malware-filter/urlhaus-filter-ag-online.txt", "http://curbengh.github.io/malware-filter/urlhaus-filter-ag-online.txt's filters", FilterGroup::Default, true),
            ("http://curbengh.github.io/phishing-filter/phishing-filter.txt", "http://curbengh.github.io/phishing-filter/phishing-filter.txt's filters", FilterGroup::Default, true),
            ("http://easylist-downloads.adblockplus.org/Liste_AR.txt", "http://easylist-downloads.adblockplus.org/Liste_AR.txt's filters", FilterGroup::Default, true),
            ("http://easylist-downloads.adblockplus.org/easylistgermany.txt", "http://easylist-downloads.adblockplus.org/easylistgermany.txt's filters", FilterGroup::Default, true),
            ("http://easylist-downloads.adblockplus.org/easylistitaly.txt", "http://easylist-downloads.adblockplus.org/easylistitaly.txt's filters", FilterGroup::Default, true),
            ("http://easylist-downloads.adblockplus.org/easylistspanish.txt", "http://easylist-downloads.adblockplus.org/easylistspanish.txt's filters", FilterGroup::Default, true),
            ("http://easylist-downloads.adblockplus.org/indianlist.txt", "http://easylist-downloads.adblockplus.org/indianlist.txt's filters", FilterGroup::Default, true),
            ("http://easylist.to/easylistgermany/easylistgermany.txt", "http://easylist.to/easylistgermany/easylistgermany.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/11.txt", "http://filters.adtidy.org/extension/ublock/filters/11.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/13.txt", "http://filters.adtidy.org/extension/ublock/filters/13.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/16.txt", "http://filters.adtidy.org/extension/ublock/filters/16.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/17.txt", "http://filters.adtidy.org/extension/ublock/filters/17.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/18.txt", "http://filters.adtidy.org/extension/ublock/filters/18.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/19.txt", "http://filters.adtidy.org/extension/ublock/filters/19.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/20.txt", "http://filters.adtidy.org/extension/ublock/filters/20.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/21.txt", "http://filters.adtidy.org/extension/ublock/filters/21.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/22.txt", "http://filters.adtidy.org/extension/ublock/filters/22.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/224.txt", "http://filters.adtidy.org/extension/ublock/filters/224.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt", "http://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/3.txt", "http://filters.adtidy.org/extension/ublock/filters/3.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/4.txt", "http://filters.adtidy.org/extension/ublock/filters/4.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/7.txt", "http://filters.adtidy.org/extension/ublock/filters/7.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/8.txt", "http://filters.adtidy.org/extension/ublock/filters/8.txt's filters", FilterGroup::Default, true),
            ("http://filters.adtidy.org/extension/ublock/filters/9.txt", "http://filters.adtidy.org/extension/ublock/filters/9.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/easylist/easylist.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/easylist/easylist.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/easylist/easyprivacy.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/easylist/easyprivacy.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/pgl.yoyo.org/as/serverlist", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/pgl.yoyo.org/as/serverlist's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/pgl.yoyo.org/as/serverlist.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/pgl.yoyo.org/as/serverlist.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/urlhaus-filter/urlhaus-filter-online.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/thirdparties/urlhaus-filter/urlhaus-filter-online.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badlists.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badlists.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badware.min.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badware.min.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badware.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/badware.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/filters.min.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/filters.min.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/filters.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/filters.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/privacy.min.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/privacy.min.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/privacy.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/privacy.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/quick-fixes.min.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/quick-fixes.min.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/quick-fixes.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/quick-fixes.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/unbreak.min.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/unbreak.min.txt's filters", FilterGroup::Default, true),
            ("http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/unbreak.txt", "http://github.com/uBlockOrigin/uAssets/raw/refs/heads/master/ublock/unbreak.txt's filters", FilterGroup::Default, true),
            ("http://malware-filter.gitlab.io/phishing-filter/phishing-filter.txt", "http://malware-filter.gitlab.io/phishing-filter/phishing-filter.txt's filters", FilterGroup::Default, true),
            ("http://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-ag-online.txt", "http://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-ag-online.txt's filters", FilterGroup::Default, true),
            ("http://malware-filter.pages.dev/urlhaus-filter-ag-online.txt", "http://malware-filter.pages.dev/urlhaus-filter-ag-online.txt's filters", FilterGroup::Default, true),
            ("http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext", "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext's filters", FilterGroup::Default, true),
            ("http://phishing-filter.pages.dev/phishing-filter.txt", "http://phishing-filter.pages.dev/phishing-filter.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt", "http://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/AnXh3L0/blocklist/master/albanian-easylist-addition/Albania.txt", "http://raw.githubusercontent.com/AnXh3L0/blocklist/master/albanian-easylist-addition/Albania.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt", "http://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/DandelionSprout/adfilt/master/SerboCroatianList.txt", "http://raw.githubusercontent.com/DandelionSprout/adfilt/master/SerboCroatianList.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/DeepSpaceHarbor/Macedonian-adBlock-Filters/master/Filters", "http://raw.githubusercontent.com/DeepSpaceHarbor/Macedonian-adBlock-Filters/master/Filters's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt", "http://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/Latvian-List/adblock-latvian/master/lists/latvian-list.txt", "http://raw.githubusercontent.com/Latvian-List/adblock-latvian/master/lists/latvian-list.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt", "http://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlocker.txt", "http://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlocker.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_ublock.txt", "http://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_ublock.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt", "http://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/brave/adblock-lists/master/custom/is.txt", "http://raw.githubusercontent.com/brave/adblock-lists/master/custom/is.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/dimisa-RUAdList/RUAdListCDN/main/lists/ruadlist.ubo.min.txt", "http://raw.githubusercontent.com/dimisa-RUAdList/RUAdListCDN/main/lists/ruadlist.ubo.min.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt", "http://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt", "http://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/easylist/ruadlist/master/RuAdList-uBO.txt", "http://raw.githubusercontent.com/easylist/ruadlist/master/RuAdList-uBO.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/easylist/ruadlist/master/cntblock.txt", "http://raw.githubusercontent.com/easylist/ruadlist/master/cntblock.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/gh-pages/Finland_adb.txt", "http://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/gh-pages/Finland_adb.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt", "http://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/swefilter/swefilter.min.txt", "http://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/swefilter/swefilter.min.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/anti-adblock.txt", "http://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/anti-adblock.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/tcptomato/ROad-Block/master/road-block-filters-light.txt", "http://raw.githubusercontent.com/tcptomato/ROad-Block/master/road-block-filters-light.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt", "http://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt's filters", FilterGroup::Default, true),
            ("http://raw.githubusercontent.com/ukrainianfilters/lists/main/combined/uBO/uBO.txt", "http://raw.githubusercontent.com/ukrainianfilters/lists/main/combined/uBO/uBO.txt's filters", FilterGroup::Default, true),
            ("http://secure.fanboy.co.nz/fanboy-antifacebook.txt", "http://secure.fanboy.co.nz/fanboy-antifacebook.txt's filters", FilterGroup::Default, true),
            ("http://secure.fanboy.co.nz/fanboy-cookiemonster_ubo.txt", "http://secure.fanboy.co.nz/fanboy-cookiemonster_ubo.txt's filters", FilterGroup::Default, true),
            ("http://secure.fanboy.co.nz/fanboy-social_ubo.txt", "http://secure.fanboy.co.nz/fanboy-social_ubo.txt's filters", FilterGroup::Default, true),
            ("http://someonewhocares.org/hosts/hosts", "http://someonewhocares.org/hosts/hosts's filters", FilterGroup::Default, true),
            ("http://stanev.org/abp/adblock_bg.txt", "http://stanev.org/abp/adblock_bg.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/annoyances-cookies.txt", "http://ublockorigin.github.io/uAssets/filters/annoyances-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/annoyances.txt", "http://ublockorigin.github.io/uAssets/filters/annoyances.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/badlists.txt", "http://ublockorigin.github.io/uAssets/filters/badlists.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/badware.txt", "http://ublockorigin.github.io/uAssets/filters/badware.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/filters.txt", "http://ublockorigin.github.io/uAssets/filters/filters.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/lan-block.txt", "http://ublockorigin.github.io/uAssets/filters/lan-block.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/privacy.txt", "http://ublockorigin.github.io/uAssets/filters/privacy.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/quick-fixes.txt", "http://ublockorigin.github.io/uAssets/filters/quick-fixes.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/filters/unbreak.txt", "http://ublockorigin.github.io/uAssets/filters/unbreak.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-annoyances.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-annoyances.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-chat.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-chat.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-cookies.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-newsletters.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-newsletters.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-notifications.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-notifications.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist-social.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist-social.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easylist.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easylist.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt", "http://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/annoyances-cookies.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/annoyances-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/annoyances.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/annoyances.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/badlists.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/badlists.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/badware.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/badware.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/lan-block.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/lan-block.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/privacy.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/privacy.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/filters/unbreak.min.txt", "http://ublockorigin.github.io/uAssetsCDN/filters/unbreak.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-annoyances.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-annoyances.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-chat.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-chat.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-cookies.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-newsletters.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-newsletters.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-notifications.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-notifications.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-social.txt", "http://ublockorigin.github.io/uAssetsCDN/thirdparties/easylist-social.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/annoyances-cookies.txt", "http://ublockorigin.pages.dev/filters/annoyances-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/annoyances.min.txt", "http://ublockorigin.pages.dev/filters/annoyances.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/badlists.txt", "http://ublockorigin.pages.dev/filters/badlists.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/badware.min.txt", "http://ublockorigin.pages.dev/filters/badware.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/filters.min.txt", "http://ublockorigin.pages.dev/filters/filters.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/lan-block.txt", "http://ublockorigin.pages.dev/filters/lan-block.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/privacy.min.txt", "http://ublockorigin.pages.dev/filters/privacy.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/quick-fixes.min.txt", "http://ublockorigin.pages.dev/filters/quick-fixes.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/filters/unbreak.min.txt", "http://ublockorigin.pages.dev/filters/unbreak.min.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-annoyances.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-annoyances.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-chat.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-chat.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-cookies.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-cookies.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-newsletters.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-newsletters.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-notifications.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-notifications.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist-social.txt", "http://ublockorigin.pages.dev/thirdparties/easylist-social.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easylist.txt", "http://ublockorigin.pages.dev/thirdparties/easylist.txt's filters", FilterGroup::Default, true),
            ("http://ublockorigin.pages.dev/thirdparties/easyprivacy.txt", "http://ublockorigin.pages.dev/thirdparties/easyprivacy.txt's filters", FilterGroup::Default, true),
            ("http://www.void.gr/kargig/void-gr-filters.txt", "http://www.void.gr/kargig/void-gr-filters.txt's filters", FilterGroup::Default, true),
        ]
        .into_iter()
        .filter_map(|(url, title, group, enabled_by_default)| Self::parse_filter(url, title, group, enabled_by_default))
        .collect()
    }
}

fn calculate_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

pub(crate) fn calc_filter_filename(filename: &str) -> String {
    format!("{}.txt", calculate_sha256_hex(filename))
}

impl Filter {
    pub(super) async fn update(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<String> {
        log::debug!("Updating filter: {}", self.title);

        let filters_directory = get_filter_directory();
        fs::create_dir_all(&filters_directory).await?;

        let filter = get_filter(self, http_client).await?;

        let filter_path = filters_directory.join(&self.file_name);
        fs::write(&filter_path, &filter).await?;

        Ok(filter)
    }

    pub async fn get_contents(
        &mut self,
        http_client: &reqwest::Client,
    ) -> super::ConfigurationResult<String> {
        let filter_path = get_filter_directory().join(&self.file_name);
        match fs::read(&filter_path).await {
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    self.update(http_client).await
                } else {
                    Err(super::ConfigurationError::FileSystemError(err))
                }
            }
            Ok(filter) => Ok(std::str::from_utf8(&filter)?.to_string()),
        }
    }
}

impl From<DefaultFilter> for Filter {
    fn from(default_filter: DefaultFilter) -> Self {
        Self {
            enabled: default_filter.enabled_by_default,
            title: default_filter.title,
            group: match default_filter.group.as_str() {
                "default" => FilterGroup::Default,
                "regional" => FilterGroup::Regional,
                "ads" => FilterGroup::Ads,
                "privacy" => FilterGroup::Privacy,
                "malware" => FilterGroup::Malware,
                "social" => FilterGroup::Social,
                _ => unreachable!(),
            },
            file_name: default_filter.file_name,
            url: default_filter.url,
        }
    }
}

pub(crate) async fn get_filter(
    filter: &mut Filter,
    http_client: &reqwest::Client,
) -> super::ConfigurationResult<String> {
    let response = http_client.get(filter.url.as_str()).send().await?;
    if response.status().is_success() {
        let content = response.text().await?;
        Ok(content)
    } else {
        log::error!("Failed to fetch filter content: {}", response.status());
        Err(super::ConfigurationError::FilterError(format!(
            "Failed to fetch filter content: {}",
            response.status()
        )))
    }
}

fn get_filter_directory() -> PathBuf {
    let filter_dir: PathBuf = match env::var("PRIVAXY_FILTER_PATH") {
        Ok(val) => PathBuf::from(&val),
        // Assume home directory
        Err(_) => PathBuf::from(FILTERS_DIRECTORY_NAME),
    };
    return super::get_base_directory().unwrap().join(filter_dir);
}

pub(crate) async fn get_filters_content(
    configuration: &mut super::Configuration,
    http_client: &reqwest::Client,
) -> Vec<String> {
    let mut filters = Vec::new();
    let mut futures = vec![];

    for filter in configuration.get_enabled_filters() {
        let future = filter.get_contents(http_client);
        futures.push(future);
    }

    let results = futures::future::join_all(futures).await;
    for result in results {
        match result {
            Ok(filter_content) => filters.push(filter_content),
            Err(err) => {
                log::error!("Unable to retrieve filter: {:?}, skipping.", err)
            }
        }
    }

    filters.append(&mut configuration.custom_filters);
    filters.sort_unstable();
    // Filter out duplicate lines, if present
    filters.dedup();
    filters
}

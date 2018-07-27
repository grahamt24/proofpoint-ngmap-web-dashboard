/**
 * @fileoverview - Generates the file info page for the website
 * @Author - Graham Thomas
 * @Dependencies - datatables.min.js, sidebarnotable.js, sitefunctions.js
 */


/**
 * Constructor for FileInfo
 * @param {string} sel
 * @param {string} id
 * @constructor
 */
function FileInfo(sel, id) {
    // for referencing FileInfo in other functions
    var that = this;

    // new HTTP Get request to the API
    var request = new XMLHttpRequest({mozSystem: true});

    // URL of the API request
    var url = 'http://10.55.200.100:3000/api/staticoutput/_id?id=' + id;

    // wait until success response to do anything
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            // parse the json of the API response and call function to do once that happens
            var response = JSON.parse(this.responseText);
            getElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();

    // array of information for the specific file
    var info = [];
    getElements = function (response) {
        info.push(response.output[0].name);
        info.push(response.output[1].extension);
        info.push(response.output[2].Yara_output);
        info.push(response.output[3].PEHash);
        info.push(response.output[4].sha256);
        info.push(response.output[5].sha1);
        info.push(response.output[6].md5);
        info.push(response.output[7].File_Size);
        info.push(response.output[8].Static_Runtime);
        info.push(parseInt(response.output[9].Cuckoo_ID));

        // get html needed for the page
        var html = that.setUpTables(info);
        $(sel).html(html);
        $("h1").html("In-Depth Analysis of " + info[0]);
        if(info[2] !== "No Matches"){
            $("#yaraoutput").DataTable({
                "pageLength": 10
            })
        }

        // generate sidebar with no table to access data from
        new SidebarNoTable();
    };
}

/**
 * Get the similar malware in a cluster for a specific PE Hash
 * @param {string} peHash
 */
FileInfo.prototype.getClusters = function (peHash) {
    // new request to the cluster API
    var request = new XMLHttpRequest({mozSystem: true});

    // URL of the cluster API
    var url = 'http://10.55.200.100:3000/api/cluster';

    // same thing as before, wait for success response
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            // parse json of the response
            var response = JSON.parse(this.responseText);
            getElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();


    getElements = function (response) {
        // iterate through the clusters from the API
        for (var key in response[0]) {
            if (response[0].hasOwnProperty(key)) {
                var html = '';
                // if the key is the PE Hash we want, begin getting information
                if (key === peHash) {
                    // array of PE Hashes that are similar to the one we have
                    var peHashes = response[0][key];
                    var request = new XMLHttpRequest({mozSystem: true});
                    var url = 'http://10.55.200.100:3000/api/staticoutput';
                    request.onreadystatechange = function () {
                        if (this.readyState === 4 && this.status === 200) {
                            var response = JSON.parse(this.responseText);
                            // add the start of the table to the html
                            html += '<thead class="thead-dark"><tr><th>File Name</th><th>PE Hash</th></tr></thead>';

                            // array of arrays for the information needed from API response
                            var overallInfo = [];

                            // iterate through the whole response to get specific files we need
                            for (var i = 0; i < response.length; i++) {
                                // information for matching PE Hash
                                var infoByPeHash = [];
                                for (var j = 0; j < peHashes.length; j++) {
                                    // get info needed for populating similar malware table
                                    if (peHashes[j] === response[i].output[3].PEHash) {
                                        infoByPeHash.push(response[i].output[3].PEHash);
                                        infoByPeHash.push(response[i].output[0].name);
                                        infoByPeHash.push(response[i]._id);
                                        overallInfo.push(infoByPeHash);
                                    }
                                }
                            }
                            // if the length is 0, it has no similar malware
                            if (overallInfo.length === 0) {
                                html += '<tbody>';
                                html += '<tr><td colspan="2">No similar malware found</td></tr>';
                            }
                            // populate the similar malware table with all the found information
                            else {
                                html += '<tbody data-link="row" class="rowlink">';
                                for (var i = 0; i < overallInfo.length; i++) {
                                    html += '<tr><td><a href="fileinfo.html?_id=' + overallInfo[i][2];
                                    html += '">' + overallInfo[i][1] + '</a>';
                                    html += '</td><td>' + overallInfo[i][0] + '</td></tr>';
                                }
                            }
                            html += '</tbody>';
                            // set the html of the div
                            $("#clusters").html(html);
                            if(overallInfo.length !== 0){
                                $("#clusters").DataTable({
                                    "pageLength": 10
                                })
                            }
                        }
                    };
                    request.open("GET", url, true);
                    request.send();
                }
            }
        }
    }
};

/**
 * Set up the tables on the file info page
 * @param {array} info
 * @returns {string}
 */
FileInfo.prototype.setUpTables = function (info) {
    // for referencing File Info
    var that = this;

    // begin first table
    var html = '<table class="table table-hover table-bordered" id="filestatistics" cellspacing="0">' +
        '<thead class="thead-dark"><tr><th>File Information</th><th>Statistic Information</th></tr></thead>';

    // FILE STATISTICS AND INFORMATION TABLE
    html += '<tbody><tr><td>File Extension</td><td>' + info[1] + '</td>' +
        '</tr><tr><td>File Size</td><td>' + info[7] + '</td></tr>' +
        '<tr><td>Static Analysis Time</td><td>' + info[8] + '</td></tr>' +
        '<tr><td>Dynamic Analysis Link</td><td>';

    if(info[9] === -1 || typeof(info[9]) === "undefined"){
        html += "Did not undergo dynamic analysis."
    }
    else{
        console.log(info[9]);
        html += '<a href="http://10.55.200.130/analysis/' + info[9] + '/summary/">Cuckoo Webpage</a>';
    }

    html += '</td></tr></tbody></table><br>';

    // FILE HASHES TABLE
    html += '<h2>File Hashes</h2><table class="table table-hover table-bordered" id="filehashes" cellspacing="0">' +
        '<thead class="thead-dark"><tr><th>Hash Types</th><th>File Hash</th></tr></thead>';

    html += '<tbody><tr><td>PE Hash</td><td> ' + info[3] + '</td>' +
        '</tr><tr><td>SHA256</td><td>' + info[4].toUpperCase() + '</td></tr><tr><td>SHA1</td>' +
        '<td>' + info[5].toUpperCase() + '</td></tr>' +
        '<tr><td>MD5</td><td>' + info[6].toUpperCase() + '</td></tr>' +
        '<tr></tbody></table><br>';

    // CLUSTERING TABLE
    html += '<h2>Similar Malware</h2><table class="table table-hover table-bordered" id="clusters" cellspacing="0"></table><br>';
    that.getClusters(info[3]);


    // YARA OUTPUT TABLE
    html += '<h2>Yara Output</h2><table class="table table-hover table-bordered" id="yaraoutput" cellspacing="0">' +
        '<thead class="thead-dark"><tr><th>Rule</th><th>Namespace</th><th>Meta</th></thead>';
    // if it's no matches, make the No matches span all 3 columns
    if (info[2] === "No Matches") {
        html += '<tbody><tr><td colspan="3">No matched Yara rules</td></tr></tbody></table><br>';
    }

    // otherwise populate the table with the rule, namespace, and FILTERED meta information
    else {
        html += '<tbody>';
        // loop through meta
        for(var i = 0; i < info[2].length; i++){
            html += '<tr>';
            html += '<td>' + info[2][i].Rule + '</td>';
            html += '<td>' + info[2][i].Namespace + '</td><td>';
            for(var key in info[2][i].Meta){
                if(info[2][i].Meta.hasOwnProperty(key)){
                    // only include items with a certain key, otherwise it's too much information
                    if(key === "author" || key === "method" || key === "family" || key === "date" ||
                        key === "description" || key === "reference"){
                        html += key.bold() + ': ' + info[2][i].Meta[key] + '; ';
                    }
                }
            }
            html += '</td></tr>';
        }
        html += '</tbody></table><br>';
    }
    return html;
};

/**
 * @fileoverview - Generates a table with given parameters (flagged, known, all)
 * @Author - Graham Thomas
 * @Dependencies - datatables.min.js, sidebarnotable.js
 */

/**
 * Constructor for FileTableGen instance
 * @param {string} sel
 * @param {string} table
 * @param {string} type
 * @constructor
 */
function FileTableGen(sel, table, type){
    // reference to FileTableGen instance
    var that = this;

    // create new HTTP request
    var request = new XMLHttpRequest({mozSystem: true});

    // URL of the API
    var url = 'http://10.55.200.100:3000/api/staticoutput';
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            // parsed response from the API
            var response = JSON.parse(this.responseText);
            getElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();

    // overall array containing necessary information for the table
    var information = [];
    getElements = function (response) {
        // if type is flagged, then we are getting ONLY the flagged files
        if(type === "flagged") {
            for (var i = 0; i < response.length; i++) {
                // Yara_output must be of type string to push into our array
                if (typeof(response[i].output[2].Yara_output) === "string") {
                    var info = [];
                    info.push(i);
                    info.push(response[i].output[0].name);
                    info.push(response[i].output[1].extension);
                    info.push(response[i].output[2].Yara_output);
                    info.push(response[i].output[3].PEHash);
                    info.push(response[i].output[4].sha256);
                    info.push(response[i].output[5].sha1);
                    info.push(response[i].output[6].md5);
                    info.push(response[i]._id);
                    information.push(info);
                }
            }
        }
        // if type is known, then we are getting ONLY the known files
        else if(type === "known") {
            for (var i = 0; i < response.length; i++) {
                // Yara_output must NOT be of type string to push into our array (i.e. Not "No Matches")
                if (typeof(response[i].output[2].Yara_output) !== "string") {
                    var info = [];
                    info.push(i);
                    info.push(response[i].output[0].name);
                    info.push(response[i].output[1].extension);
                    info.push(response[i].output[2].Yara_output);
                    info.push(response[i].output[3].PEHash);
                    info.push(response[i].output[4].sha256);
                    info.push(response[i].output[5].sha1);
                    info.push(response[i].output[6].md5);
                    info.push(response[i]._id);
                    information.push(info);
                }
            }
        }
        else{
            for (var i = 0; i < response.length; i++) {
                // all the information received from API response
                var info = [];
                info.push(i);
                info.push(response[i].output[0].name);
                info.push(response[i].output[1].extension);
                info.push(response[i].output[2].Yara_output);
                info.push(response[i].output[3].PEHash);
                info.push(response[i].output[4].sha256);
                info.push(response[i].output[5].sha1);
                info.push(response[i].output[6].md5);
                info.push(response[i]._id);
                information.push(info);
            }
        }
        // set up the table
        var html = that.setUpTable(information, type);
        $(sel).html(html);

        // set up the DataTable
        $(table).DataTable({
            "pageLength": 50
        });
        new SidebarNoTable();
    };
}


/**
 * Generate the html required for the table - does similar things to setUpTable in RealTime and Index
 * @param {array} tableInfo
 * @param {string} type
 * @returns {string}
 */
FileTableGen.prototype.setUpTable = function (tableInfo, type) {
    var that = this;
    // set up HTML with correct amount of headers (4 or 5) depending on what file table type it is
    var html = '<table class="table table-hover table-bordered"'
        + ' id="malwareTable" cellspacing="0"><thead class="thead-dark"><tr><th>SID'
        + '</th><th>File Name</th><th >File Type</th>'
        + '<th># of YARA Matches</th>';
    if(type === "all"){
        html += '<th>Flagged?</th></tr></tbody>';
    }
    else{
        html += '</tr></tbody>';
    }

    // set up HTML to be generated in the loop
    var loopHtml = '<tbody data-link="row" class="rowlink">';
    for (var i = 0; i < tableInfo.length; i++) {
        loopHtml += '<tr>';

        // number of loops needed
        var loopNum = 0;

        // if it's "all" it needs to loop 5 times, otherwise it's only 4 times
        if(type === "all"){
            loopNum = 5;
        }
        else{
            loopNum = 4;
        }

        // loop 4 or 5 times depending on file table needs
        for (var j = 0; j < loopNum; j++) {
            loopHtml += '<td>';

            // get the link to the file page
            if (j === 0) {
                // seen ID of the file
                var sid = tableInfo[i][0] + 1;
                loopHtml += '<a href="fileinfo.html?_id=';
                loopHtml += tableInfo[i][8] + '">' + sid;
                loopHtml += '</a>';
            }

            // file name
            if (j === 1) {
                loopHtml += tableInfo[i][j];
            }

            // file type
            if (j === 2) {
                loopHtml += tableInfo[i][j];
            }

            // number of Yara rules matched
            if (j === 3) {
                if (typeof(tableInfo[i][3]) === "string") {
                    loopHtml += 0;
                }
                else {
                    loopHtml += tableInfo[i][3].length;
                }
            }

            // only for all type, if it's a string, it's flagged if it's not it's not flagged
            if(j === 4){
                if(typeof(tableInfo[i][3]) === "string"){
                    loopHtml += "Yes";
                }
                else{
                    loopHtml += "No";
                }
            }
            loopHtml += '</td>';
        }
        loopHtml += '</tr>';
    }
    html += loopHtml;
    html += '</tbody></table>';
    return html;
};
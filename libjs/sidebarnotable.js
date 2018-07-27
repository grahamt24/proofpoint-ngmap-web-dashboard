/**
 * @fileoverview - Generates the sidebar of the website with no table information to use
 * @Author - Graham Thomas
 * @Dependencies - feather.min.js
 */

/**
 * Constructor for the SidebarNoTable instance
 * @constructor
 */
function SidebarNoTable() {
    // for referencing SidebarNoTable instance
    var that = this;

    // start of the html string
    var html = "";

    // new request to the API
    var request = new XMLHttpRequest({mozSystem: true});

    // url of the API
    var url = 'http://10.55.200.100:3000/api/staticoutput';

    // wait until it is ready to do anything with the sidebar
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            var response = JSON.parse(this.responseText);
            getSidebarElements(response);
        }
    };
    request.open("GET", url, true);
    request.send();

    // HTML of the flagged file portion of the sidebar
    var flaggedFileHTML = "";

    // HTML of the known file portion of the sidebar
    var knownFileHTML = "";

    // count of the known files
    var knownFileCount = 0;

    // count of the flagged files
    var flaggedFileCount = 0;

    getSidebarElements = function (response) {
        // loop through response
        for (var i = 0; i < response.length; i++) {
            // if it's a string, it is "No Matches", so it is a flagged file
            //console.log(typeof(response[i].output[2].Yara_output));
            if(typeof(response[i].output[2].Yara_output) === "string"){
                // don't add any additional files to the sidebar after 9
                if(flaggedFileCount < 9){
                    flaggedFileHTML += that.generateHTML(response[i]);
                }
                // always increment count
                flaggedFileCount++;
            }
            else{
                // don't add any additional files to the sidebar after 9
                if(knownFileCount < 9){
                    knownFileHTML += that.generateHTML(response[i]);
                }
                // always increment count
                knownFileCount++;
            }
            if(knownFileCount > 9 && flaggedFileCount > 9){
                break;
            }
        }
        // ensure the knownFileCount incremented properly and finish that part of the sidebar
        if(knownFileCount >= 9){
            // count the total number of known files
            var total = that.countKnown(response);
            knownFileHTML += '<li class="nav-item"><a class="nav-link" href="knownmalware.html">' +
                ' And ' + (total-9) + ' more files...</a></li>';
        }
        if(flaggedFileCount >= 9){
            // count the total number of flagged files
            var total = that.countFlagged(response);
            flaggedFileHTML += '<li class="nav-item"><a class="nav-link" href="flaggedfiles.html">' +
                'And ' + (total-9) + ' more files...</a></li>';
        }
        // set the html of the div to the corresponding html
        $("#flaggedfiles").html(flaggedFileHTML);
        $("#knownfiles").html(knownFileHTML);
        feather.replace();
    }
}

/**
 * Generates the html for the sidebar
 * @param {object} data
 * @returns {string}
 */
SidebarNoTable.prototype.generateHTML = function (data) {
    // beginning of the html
    var html = "";
    html += '<li class="nav-item">';

    // get the id of the current page we are on
    var fileID = findGetParameter("_id");

    // if the current page is the one that is selected, set the link to be "active" (to appear in blue)
    if (fileID === data._id) {
        html += '<a class="nav-link text-truncate active" href="fileinfo.html?_id=' + fileID + '" style="max-width: 325px">';
    }
    else {
        html += '<a class="nav-link text-truncate" href="fileinfo.html?_id=' + data._id + '" style="max-width: 325px">';
    }

    // get the feather icon next to it and then add the file name to the list
    html += '<span data-feather="file"></span>';
    html += data.output[0].name;
    html += '</a></li>';

    return html;
};

/**
 * Count the number of flagged files in a data set
 * @param {array} data
 * @returns {number}
 */
SidebarNoTable.prototype.countFlagged = function (data){
    // initialize count
    var count = 0;
    for(var i = 0; i < data.length; i++) {
        // if it's a string, it's "No Matches" therefore we increment count
        if (typeof(data[i].output[2].Yara_output) === "string") {
            count++;
        }
    }
    return count;
};

/**
 * Count the number of Known files in a data set
 * @param {array} data
 * @returns {number}
 */
SidebarNoTable.prototype.countKnown = function (data){
    // initialize count
    var count = 0;
    for(var i = 0; i < data.length; i++) {
        // if it's not a string, increment count since Yara_output is an object when a yara rule is matched.
        if (typeof(data[i].output[2].Yara_output) !== "string") {
            count++;
        }
    }
    return count
};
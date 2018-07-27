/**
 * @fileoverview - Generates the sidebar of the website with table information to use
 * @Author - Graham Thomas
 * @Dependencies - feather.min.js
 */


/**
 * Constructor for the SidebarWithTable instance
 * @param {string} sel
 * @param {string} table
 * @constructor
 */
function SidebarWithTable(sel, table) {
    // referencing SidebarWithTable
    var that = this;

    // get the data from the table
    var data = table.rows().data();

    // begin html string
    var html = "";

    // determine whether we are setting up flagged portion of the sidebar or the known files portion
    if(sel === "#flaggedfiles"){
        // number of flagged files
        var flagged = 0;

        // loop through, if it has encountered more than 9 files, break out (since we only want 9 to show)
        for(var i = 0; i < data.length; i++) {
            if(flagged >= 9){
                break;
            }
            if (data[i][3] === "Yes") {
                html += that.generateHTML(data[i]);
                flagged++;
            }
        }

        // count total number of flagged files and add the link to the "flagged files" page
        if(flagged >= 9){
            var total = that.countFlagged(data);
            html += '<li class="nav-item"><a class="nav-link" href="flaggedfiles.html">' +
                'And ' + (total-9) + ' more files...</a></li>';
        }
    }
    else if(sel === "#knownfiles"){
        // number of known files
        var known = 0;

        // loop through, if it has encountered more than 9 files, break out (since we only want 9 to show)
        for(var i = 0; i < data.length; i++){
            if(known >= 9){
                break;
            }
            if(data[i][3] === "No"){
                html += that.generateHTML(data[i])
                known++;
            }
        }

        // count total number of known files and add the link to the "known files" page
        if(known >= 9){
            var total = that.countKnown(data);
            html += '<li class="nav-item"><a class="nav-link" href="knownmalware.html">' +
                'And ' + (total-9) + ' more files...</a></li>';
        }
    }
    // set the sidebar html and give them icons
    $(sel).html(html);
    feather.replace();
}


/**
 * Generate the HTML for the sidebar
 * @param {array} data
 * @returns {string}
 */
SidebarWithTable.prototype.generateHTML = function (data){
    // start of the html
    var html = "";
    html += '<li class="nav-item">';

    // get the link to the page we need
    var aHref = data[0];

    // id of the file in the database
    var id = "";

    // determine when we need to start getting characters for the id
    var startCollecting = false;
    for (var j = 0; j < aHref.length; j++) {
        // if it's an _ we are at "_id?" so we must start collecting
        if (aHref[j] === '_') {
            startCollecting = true;
        }
        // if it's an " we are at the end of the string
        else if (aHref[j] === '"') {
            startCollecting = false;
        }
        // if we need to collect, add the character to the id string
        if (startCollecting) {
            id += aHref[j];
        }
    }
    if(data[1] === "C6A13AFC5831096B0CCB54FBB2B3D14E4BA06E9C7A363C884B1383C5EE81FAA"){
        html += '<a class="nav-link text-truncate" href="http://10.55.200.120:437/analysis/53/summary/" style="max-width: 325px">'
    }
    else {
        html += '<a class="nav-link text-truncate" href="fileinfo.html?' + id + '" style="max-width: 325px">';
    }
    html += '<span data-feather="file"></span>';
    html += data[1];
    html += '</a></li>';

    return html;
};

/**
 * Count the total number of flagged files in the table
 * @param {array} data
 * @returns {number}
 */
SidebarWithTable.prototype.countFlagged = function (data){
    // total number of files
    var count = 0;
    for(var i = 0; i < data.length; i++) {
        // it is flagged, so increment count
        if (data[i][3] === "Yes") {
            count++;
        }
    }
    return count;
};

/**
 * Count the total number of known files in the database
 * @param {array} data
 * @returns {number}
 */
SidebarWithTable.prototype.countKnown = function (data){
    // total number of files
    var count = 0;
    for(var i = 0; i < data.length; i++) {
        // it's not flagged so it is known, increment count
        if (data[i][3] === "No") {
            count++;
        }
    }
    return count
};
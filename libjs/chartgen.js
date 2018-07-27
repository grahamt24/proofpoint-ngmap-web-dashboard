function chartGen(sel){
	var that = this;
	var ctx = document.getElementById(sel);

	var request = new XMLHttpRequest({mozSystem: true});
    var url = 'http://10.55.200.100:3000/api/staticoutput';
    request.onreadystatechange = function() {
    	if (this.readyState === 4 && this.status === 200) {
      		var response = JSON.parse(this.responseText);
        	getElements(response);
		}
   	}
    request.open("GET", url, true);
    request.send();
	var information = [];
    getElements = function(response) {
      	for(var i = 0; i < response.length; i++){
			if(typeof(response[i].output[2].Yara_output) === "string"){
				information.push(response[i].output[2].Yara_output);
			}
			else{
				information.push(response[i].output[2].Yara_output.Rule);
			}
		}
		var noDupYara = information.filter(function(item, i, ar){
			return ar.indexOf(item) === i;
		});
		var yaraCounts = []
		for(var i = 0; i < noDupYara.length; i++){
			var count = that.countYaraRules(noDupYara[i], information);
			yaraCounts.push(count);
		}
		that.generateChart(ctx, noDupYara, yaraCounts);
	}
}

chartGen.prototype.generateChart = function(ctx, info, counts){
	    var myChart = new Chart(ctx, {
		type: 'bar',
        data: {
        labels: info,
       	datasets: [{
        	data: counts,
            borderColor: '#007bff',
            borderWidth: 4,
            pointBackgroundColor: '#007bff'
        }]
        },
        options: {
		  animation: {
				duration: 0
		  },
		  legend: {
				display: true
		  },
          layout: {
			padding: {
				left: 0,
				right: 100,
				top: 0,
				bottom: 0
			}
		  }
        }
      });
}

chartGen.prototype.countYaraRules = function(rule, info){
	var count = 0;
	for(var i = 0; i < info.length; i++){
		if(info[i] == rule){
			count++;
		}
	}
	return count;
}

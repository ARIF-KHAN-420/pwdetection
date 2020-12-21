window.onload = function() {

    var chart = new CanvasJS.Chart("chartContainer", {
        theme: "light1", // "light1", "light2", "dark1", "dark2"
        exportEnabled: true,
        animationEnabled: true,
        title: {
            text: "Pageviews by Browser"
        },
        data: [{
            type: "pie",
            startAngle: 25,
            toolTipContent: "<b>{label}</b>: {y}%",
            showInLegend: "true",
            legendText: "{label}",
            indexLabelFontSize: 12,
            indexLabel: "{label} - {y}%",
            dataPoints: [
                { y: 51.08, label: "Chrome" },
                { y: 27.34, label: "Internet Explorer" },
                { y: 10.62, label: "Firefox" },
                { y: 5.02, label: "Microsoft Edge" },
                { y: 4.07, label: "Safari" },
                { y: 1.22, label: "Opera" },
                { y: 0.44, label: "Others" }
            ]
        }]
    });
    var chart2 = new CanvasJS.Chart("chartContainer2", {
        theme: "light1", // "light1", "light2", "dark1", "dark2"
        exportEnabled: true,
        animationEnabled: true,
        title: {
            text: "Users by Country"
        },
        data: [{
            type: "column",
            startAngle: 20,
            toolTipContent: "<b>{label}</b>: {y}",
            showInLegend: "true",
            legendText: "{label}",
            indexLabelFontSize: 12,
            indexLabel: "{label} - {y}",
            dataPoints: [
                { y: 5108, label: "Bangladesh" },
                { y: 2734, label: "China" },
                { y: 1062, label: "India" },
                { y: 502, label: "Japan" },
                { y: 407, label: "korea" },
                { y: 192, label: "UK" },
                { y: 144, label: "Iran" },
                { y: 174, label: "Iraq" },
                { y: 244, label: "UAE" },
                { y: 144, label: "Canada" },
                { y: 844, label: "Peru" },
                { y: 440, label: "Brazil" },
                { y: 194, label: "Argentina" },
                { y: 1194, label: "Denmark" }
            ]
        }]
    });
    var chart3 = new CanvasJS.Chart("chartContainer3", {
        theme: "light1", // "light1", "light2", "dark1", "dark2"
        exportEnabled: true,
        animationEnabled: true,
        title: {
            text: "Pageviews by Operating Systems"
        },
        data: [{
            type: "pie",
            startAngle: 20,
            toolTipContent: "<b>{label}</b>: {y}",
            showInLegend: "true",
            legendText: "{label}",
            indexLabelFontSize: 12,
            indexLabel: "{label} - {y}",
            dataPoints: [
                { y: 5108, label: "Windows" },
                { y: 2734, label: "iOS" },
                { y: 3062, label: "Android" },
                { y: 502, label: "Linux" }
            ]
        }]
    });
    chart.render();
    chart2.render();
    chart3.render();

}
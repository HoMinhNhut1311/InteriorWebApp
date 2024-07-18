import { useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';

const ChartComponent = ({ labels, data }) => {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    if (chartRef.current) {
      const ctx = chartRef.current.getContext('2d');
      if (ctx) {
        if (chartInstance.current) {
          chartInstance.current.destroy();
        }
        chartInstance.current = new Chart(ctx, getChartConfig(labels, data));
      }
    }

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [labels, data]);

  const getChartConfig = (labels, data) => {
    return {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Doanh thu',
            data: data,
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1,
          },
        ],
      },
      options: {
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    };
  };

  return <canvas ref={chartRef} />;
};

export default ChartComponent;

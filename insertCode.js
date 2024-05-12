const fs = require('fs');
const path = require('path');

fs.readFile('generated-code.txt', 'utf8', (err, file) => {
    if (err) {
      console.error(err);
      return;
    }
    // Split the content into an array of lines
    const lines = file.split('\n');
    const dataArr = [];
    let currentSnippet = {};

    lines.forEach((line) => {
      if (line.startsWith('Code Snippet')) {
        if (Object.keys(currentSnippet).length > 0) {
          dataArr.push(currentSnippet);
        }
        currentSnippet = {
          snippet: line.replace('Code Snippet ', ''),
          file: '',
          code: ''
        };
      } else if (line.startsWith('Folder/File Structure:')) {
        currentSnippet.file = line.replace('Folder/File Structure: ', '');
      } else {
        currentSnippet.code += line + '\n';
      }
    });
    
    if (Object.keys(currentSnippet).length > 0) {
      dataArr.push(currentSnippet);
    }
    
Object.keys(dataArr).forEach((index) => {
  const data = dataArr[index];
  const dirArr = data.file.split('/');
  const lastIndex = dirArr.length - 1;
  const dir = dirArr.slice(0, lastIndex).join('/');
  const path = data.file.slice(0, -1);
  console.log(111, dir);
  console.log(222, path);

  fs.mkdir(dir, (err) => {
    if (err) {
      console.error(err);
      return;
    }
    console.log(`Directory created: ${dir}`);
  
    // Create a new file
      fs.writeFile(path, data.code, (err) => {
      if (err) {
        console.error(err);
      } else {
        console.log(`File created: ${path}`);
      }
    })
  });
});
});

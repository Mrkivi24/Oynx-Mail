// static/js/main.js
document.addEventListener("DOMContentLoaded", function(){
  // simple client-side form validation for compose
  const composeForm = document.querySelector('form[enctype="multipart/form-data"]');
  if (composeForm) {
    composeForm.addEventListener('submit', function(e){
      const recipient = composeForm.querySelector('input[name="recipient"]');
      if (!recipient || recipient.value.trim() === '') {
        e.preventDefault();
        alert("Please provide a recipient username.");
      }
    });
  }
});

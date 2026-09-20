const observer=new IntersectionObserver(entries=>{
  entries.forEach(entry=>{
    if(entry.isIntersecting) entry.target.classList.add('in');
  });
},{threshold:.1});
document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));

document.querySelectorAll('esp-web-install-button').forEach(button=>{
  button.addEventListener('click',()=>{
    button.closest('.install')?.classList.add('installer-active');
  });
});

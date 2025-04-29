import { Router } from 'express';

const homeController = Router();

homeController.get('/', (req, res) => {
    res.render('home', {title : 'Home Page'});
});

homeController.get('/about', (req, res) => {
    res.render('home/about', {title: 'About'});
})

export default homeController;